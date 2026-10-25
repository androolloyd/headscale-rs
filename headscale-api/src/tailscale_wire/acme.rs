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
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
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
    http01_router_with_host_policy(store, None)
}

pub fn http01_router_with_host_policy(
    store: AcmeHttp01ChallengeStore,
    allowed_host: Option<String>,
) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(handle_http01_challenge),
        )
        .with_state(Http01RouterState {
            store,
            host_policy: allowed_host.map_or(Http01HostPolicy::Any, |host| {
                host_whitelist_name(&host)
                    .map_or(Http01HostPolicy::NoneAllowed, Http01HostPolicy::Host)
            }),
        })
}

/// autocert's `HostWhitelist` keeps each configured name as
/// `idna.Lookup.ToASCII` renders it and omits names that conversion rejects.
#[cfg(feature = "full")]
fn host_whitelist_name(host: &str) -> Option<String> {
    super::tls::host_whitelist_name(host)
}

// The IDNA conversion is `full`-only, so without it the name is kept as
// configured and cannot be rejected; the signature stays shared with the
// `full` build, where it can.
#[cfg(not(feature = "full"))]
#[allow(clippy::unnecessary_wraps)]
fn host_whitelist_name(host: &str) -> Option<String> {
    Some(host.to_owned())
}

#[derive(Clone, Debug)]
enum Http01HostPolicy {
    /// No host policy: every request `Host` is served.
    Any,
    /// autocert `HostWhitelist` form of the configured name.
    Host(String),
    /// The configured name failed conversion; autocert's whitelist is then
    /// empty and no request host is allowed.
    NoneAllowed,
}

pub fn http01_listener_router(
    store: AcmeHttp01ChallengeStore,
    redirect_base_url: Option<String>,
    allowed_host: Option<String>,
) -> Router {
    let router = http01_router_with_host_policy(store, allowed_host);
    let Some(redirect_base_url) = redirect_base_url else {
        return router;
    };
    router.fallback(move |uri: Uri| {
        let redirect_base_url = redirect_base_url.clone();
        async move { redirect_to_control(&redirect_base_url, &uri) }
    })
}

#[derive(Clone, Debug)]
struct Http01RouterState {
    store: AcmeHttp01ChallengeStore,
    host_policy: Http01HostPolicy,
}

async fn handle_http01_challenge(
    State(state): State<Http01RouterState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !host_policy_allows(&state.host_policy, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(key_authorization) = state.store.get(&token) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        key_authorization,
    )
        .into_response()
}

fn host_policy_allows(policy: &Http01HostPolicy, headers: &HeaderMap) -> bool {
    let allowed_host = match policy {
        Http01HostPolicy::Any => return true,
        Http01HostPolicy::Host(host) => host,
        Http01HostPolicy::NoneAllowed => return false,
    };
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|host| host == allowed_host)
}

fn redirect_to_control(base_url: &str, uri: &Uri) -> Response {
    let mut location = base_url.to_string();
    location.push_str(uri.path_and_query().map_or("/", |path| path.as_str()));

    let Ok(location) = HeaderValue::from_str(&location) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response
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

    #[tokio::test]
    async fn http01_router_enforces_allowed_host_for_registered_tokens() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let app = http01_router_with_host_policy(store, Some("control.example".into()));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .header(header::HOST, "control.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"token-123.thumbprint");
    }

    /// autocert's `HostWhitelist` stores each configured name through
    /// `idna.Lookup.ToASCII` and `HTTPHandler` compares the request `Host`
    /// against that form, so a mixed-case `tls_letsencrypt_hostname` still
    /// serves the validator's lowercase request.
    #[cfg(feature = "full")]
    #[tokio::test]
    async fn http01_router_normalizes_configured_host_like_autocert() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let app = http01_router_with_host_policy(store, Some("Control.Example".into()));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .header(header::HOST, "control.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn http01_router_rejects_wrong_host_before_serving_token() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let app = http01_router_with_host_policy(store, Some("control.example".into()));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .header(header::HOST, "other.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn http01_router_returns_not_found_for_unknown_token_on_allowed_host() {
        let app = http01_router_with_host_policy(
            AcmeHttp01ChallengeStore::new(),
            Some("control.example".into()),
        );

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/missing")
                    .header(header::HOST, "control.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http01_listener_redirects_non_challenge_paths_to_control_url() {
        let app = http01_listener_router(
            AcmeHttp01ChallengeStore::new(),
            Some("https://control.example".into()),
            Some("control.example".into()),
        );

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=138")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("https://control.example/key?v=138")
        );
    }

    #[tokio::test]
    async fn http01_listener_returns_not_found_without_redirect_base_url() {
        let app = http01_listener_router(AcmeHttp01ChallengeStore::new(), None, None);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=138")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
