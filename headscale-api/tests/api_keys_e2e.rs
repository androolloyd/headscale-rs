//! End-to-end coverage for headscale-go-compatible API keys.

#![cfg(feature = "admin")]

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use headscale_api::admin::{
    AdminState, InMemoryPreauthAdmin, PersistentApiKeyAdmin, UserRegistry, WireMachineAdmin, router,
};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::MachineRegistry;
use headscale_db::Database;
use tower::ServiceExt;

const BEARER: &str = "api-key-e2e-bearer";

async fn fixture() -> Router {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");
    let api_keys = PersistentApiKeyAdmin::new_for_test(db.pool().clone());
    let reg = Arc::new(MachineRegistry::new());
    let state = AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .api_keys(Arc::new(api_keys))
        .derp_regions(0)
        .policy(PolicyStore::new())
        .build();
    router(state)
}

async fn body_text(resp: Response) -> String {
    let b = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

async fn body_json(resp: Response) -> serde_json::Value {
    let text = body_text(resp).await;
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("not json: {e}\n{text}"))
}

fn req(method: Method, uri: &str, token: &str, body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

#[tokio::test]
async fn api_key_create_list_auth_expire_and_delete_flow() {
    let app = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey",
            BEARER,
            r#"{"expiration":"2999-01-01T00:00:00Z"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let api_key = created["api_key"].as_str().expect("api_key").to_string();
    assert!(api_key.starts_with("hskey-api-"));

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/apikey", &api_key, Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    let prefix = list["api_keys"][0]["prefix"]
        .as_str()
        .expect("display prefix")
        .to_string();
    assert!(prefix.starts_with("hskey-api-"));
    assert!(prefix.ends_with("-***"));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey/expire",
            &api_key,
            format!(r#"{{"prefix":"{prefix}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/apikey", &api_key, Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            &format!("/api/v1/apikey/{prefix}"),
            BEARER,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(req(Method::GET, "/api/v1/apikey", BEARER, Body::empty()))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert!(list["api_keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn api_key_delete_accepts_id_body() {
    let app = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey",
            BEARER,
            r#"{"expiration":"2999-01-01T00:00:00Z"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/apikey", BEARER, Body::empty()))
        .await
        .unwrap();
    let list = body_json(resp).await;
    let id = list["api_keys"][0]["id"].as_u64().expect("api key id");

    let resp = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            "/api/v1/apikey",
            BEARER,
            format!(r#"{{"id":{id}}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(req(Method::GET, "/api/v1/apikey", BEARER, Body::empty()))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert!(list["api_keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn api_key_rejects_missing_auth_and_bad_create_expiration() {
    let app = fixture().await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/apikey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey",
            BEARER,
            r#"{"expiration":"not-a-date"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
