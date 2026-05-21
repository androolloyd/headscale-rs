//! grpc-gateway-compatible `/api/v1` route coverage.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use headscale_api::admin::{
    ApiKeyAdmin, ApiKeyMintRequest, PersistentApiKeyAdmin, PersistentPreauthAdmin,
    PersistentUserAdmin, WireMachineAdmin,
};
use headscale_api::grpc::upstream::HeadscaleAdminService;
use headscale_api::grpc_gateway;
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::MachineRegistry;
use serde_json::Value;
use tower::ServiceExt;

async fn fixture() -> (Router, String) {
    let db = headscale_db::Database::in_memory()
        .await
        .expect("open in-memory db");
    db.migrate().await.expect("migrate");

    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    let api_keys = Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone()));
    let created = api_keys
        .mint(ApiKeyMintRequest { expiration: None })
        .await
        .expect("mint api key");
    let preauth = Arc::new(
        PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone()),
    );
    let machines = Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new())));
    let service = HeadscaleAdminService::with_user_admin(
        users,
        api_keys,
        preauth,
        PolicyStore::new(),
        machines,
    );
    (grpc_gateway::router(service), created.api_key)
}

fn req(method: Method, uri: &str, token: Option<&str>, body: impl Into<Body>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

async fn body_json(resp: Response) -> Value {
    let body = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "response body was not JSON: {e}\n{}",
            String::from_utf8_lossy(&body)
        )
    })
}

#[tokio::test]
async fn grpc_gateway_health_requires_bearer_and_returns_protojson_status() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/health", None, Body::empty()))
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Authorization token is not supplied")
    );
    let body = body_json(resp).await;
    assert_eq!(body["code"], 16);
    assert_eq!(body["message"], "Authorization token is not supplied");
    assert_eq!(body["details"].as_array().unwrap().len(), 0);

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/health",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["databaseConnectivity"], true);
}

#[tokio::test]
async fn grpc_gateway_user_crud_uses_upstream_singular_paths() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(
                r#"{"name":"alice","displayName":"Alice Smith","email":"alice@example.com","pictureUrl":"https://example.com/alice.png"}"#,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["id"], "1");
    assert_eq!(body["user"]["name"], "alice");
    assert_eq!(body["user"]["displayName"], "Alice Smith");
    assert_eq!(
        body["user"]["profilePicUrl"],
        "https://example.com/alice.png"
    );
    assert!(body["user"]["createdAt"].as_str().unwrap().ends_with('Z'));

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/api/v1/user?name=alice",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["users"].as_array().unwrap().len(), 1);
    assert_eq!(body["users"][0]["id"], "1");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user/1/rename/bob",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["id"], "1");
    assert_eq!(body["user"]["name"], "bob");

    let resp = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            "/api/v1/user/1",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/user",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["users"], serde_json::json!([]));
}

#[tokio::test]
async fn grpc_gateway_path_parameter_type_mismatch_is_status_json() {
    let (app, token) = fixture().await;

    let resp = app
        .oneshot(req(
            Method::DELETE,
            "/api/v1/user/not-a-number",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = body_json(resp).await;
    assert_eq!(body["code"], 3);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("type mismatch, parameter: id")
    );
    assert_eq!(body["details"], serde_json::json!([]));
}
