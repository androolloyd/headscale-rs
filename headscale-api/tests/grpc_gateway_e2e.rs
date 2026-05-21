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
use headscale_api::grpc::upstream::{DatabaseHealthCheck, HeadscaleAdminService};
use headscale_api::grpc_gateway;
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::MachineRegistry;
use serde_json::Value;
use tower::ServiceExt;

struct FailingDatabaseHealth;

#[async_trait::async_trait]
impl DatabaseHealthCheck for FailingDatabaseHealth {
    async fn ping(&self) -> Result<(), String> {
        Err("forced offline".to_string())
    }
}

async fn fixture() -> (Router, String) {
    let (app, token, _db) = fixture_with_db().await;
    (app, token)
}

async fn fixture_with_db() -> (Router, String, headscale_db::Database) {
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
    )
    .with_database_pool(db.pool().clone())
    .with_policy_pool(db.pool().clone());
    (grpc_gateway::router(service), created.api_key, db)
}

async fn fixture_with_failing_health() -> (Router, String) {
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
    )
    .with_database_health(Arc::new(FailingDatabaseHealth));
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
async fn grpc_gateway_health_surfaces_database_ping_failure() {
    let (app, token) = fixture_with_failing_health().await;

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/health",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    let body = body_json(resp).await;
    assert_eq!(body["code"], 2);
    assert_eq!(body["message"], "database ping failed: forced offline");
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

#[tokio::test]
async fn grpc_gateway_node_and_debug_paths_use_upstream_shapes() {
    let (app, token) = fixture().await;
    let registration_key = "abcdefghijklmnopqrstuvwx";

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"node-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/debug/node",
            Some(&token),
            Body::from(format!(
                r#"{{"user":"node-user","key":"{registration_key}","name":"debug-router","routes":["10.10.0.0/24"]}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let node_id = body["node"]["id"].as_str().unwrap().to_string();
    assert!(!node_id.is_empty());
    assert!(
        body["node"]["machineKey"]
            .as_str()
            .unwrap()
            .starts_with("mkey:")
    );
    assert!(
        body["node"]["nodeKey"]
            .as_str()
            .unwrap()
            .starts_with("nodekey:")
    );
    assert_eq!(body["node"]["name"], "debug-router");
    assert_eq!(body["node"]["givenName"], "debug-router");
    assert_eq!(body["node"]["user"]["name"], "node-user");
    assert_eq!(
        body["node"]["registerMethod"],
        "REGISTER_METHOD_UNSPECIFIED"
    );
    assert_eq!(
        body["node"]["availableRoutes"],
        serde_json::json!(["10.10.0.0/24"])
    );
    assert_eq!(body["node"]["approvedRoutes"], serde_json::json!([]));
    assert_eq!(body["node"]["subnetRoutes"], serde_json::json!([]));
    assert!(body["node"]["createdAt"].as_str().unwrap().ends_with('Z'));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/register?user=node-user&key={registration_key}"),
            Some(&token),
            Body::from(r#"{"ignored":true}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["id"], node_id);
    assert_eq!(body["node"]["registerMethod"], "REGISTER_METHOD_CLI");

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/api/v1/node?user=node-user",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(body["nodes"][0]["id"], node_id);

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            &format!("/api/v1/node/{node_id}"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["id"], node_id);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/tags"),
            Some(&token),
            Body::from(r#"{"tags":["tag:router"]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["tags"], serde_json::json!(["tag:router"]));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/approve_routes"),
            Some(&token),
            Body::from(r#"{"routes":["10.10.0.0/24"]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(
        body["node"]["approvedRoutes"],
        serde_json::json!(["10.10.0.0/24"])
    );
    assert_eq!(
        body["node"]["subnetRoutes"],
        serde_json::json!(["10.10.0.0/24"])
    );

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/rename/new-router"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["name"], "new-router");
    assert_eq!(body["node"]["givenName"], "new-router");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/expire?expiry=2030-01-02T03%3A04%3A05Z"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["expiry"], "2030-01-02T03:04:05Z");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/node/backfillips?confirmed=true",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({ "changes": [] }));

    let resp = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            &format!("/api/v1/node/{node_id}"),
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
            "/api/v1/node",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["nodes"], serde_json::json!([]));
}

#[tokio::test]
async fn grpc_gateway_preauth_paths_use_upstream_shapes() {
    let (app, token) = fixture().await;

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"preauth-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/preauthkey",
            Some(&token),
            Body::from(r#"{"user":"1","reusable":true,"ephemeral":true,"aclTags":["tag:test"]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["preAuthKey"]["id"], "1");
    assert_eq!(body["preAuthKey"]["user"]["id"], "1");
    assert_eq!(body["preAuthKey"]["user"]["name"], "preauth-user");
    assert_eq!(body["preAuthKey"]["reusable"], true);
    assert_eq!(body["preAuthKey"]["ephemeral"], true);
    assert_eq!(body["preAuthKey"]["used"], false);
    assert_eq!(
        body["preAuthKey"]["aclTags"],
        serde_json::json!(["tag:test"])
    );
    assert!(
        body["preAuthKey"]["key"]
            .as_str()
            .unwrap()
            .starts_with("hskey-auth-")
    );

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/api/v1/preauthkey",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["preAuthKeys"].as_array().unwrap().len(), 1);
    assert_eq!(body["preAuthKeys"][0]["id"], "1");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/preauthkey/expire",
            Some(&token),
            Body::from(r#"{"id":"1"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::DELETE,
            "/api/v1/preauthkey?id=1",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));
}

#[tokio::test]
async fn grpc_gateway_apikey_paths_use_protojson_names() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey",
            Some(&token),
            Body::from("{}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let new_key = body["apiKey"].as_str().unwrap().to_string();
    assert!(new_key.starts_with("hskey-api-"));

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/api/v1/apikey",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let keys = body["apiKeys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let new_key_row = keys
        .iter()
        .find(|key| key["id"] == "2")
        .expect("new key row");
    let new_prefix = new_key_row["prefix"].as_str().unwrap().to_string();
    assert!(new_prefix.starts_with("hskey-api-"));
    assert!(new_key_row["createdAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(new_key_row["expiration"], serde_json::Value::Null);
    assert_eq!(new_key_row["lastSeen"], serde_json::Value::Null);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey/expire",
            Some(&token),
            Body::from(r#"{"id":"2"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::DELETE,
            &format!("/api/v1/apikey/{new_prefix}"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));
}

#[tokio::test]
async fn grpc_gateway_policy_round_trips_protojson_body() {
    let (app, token) = fixture().await;
    let policy = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;

    let resp = app
        .clone()
        .oneshot(req(
            Method::PUT,
            "/api/v1/policy",
            Some(&token),
            Body::from(serde_json::json!({ "policy": policy }).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["policy"], policy);
    assert!(body["updatedAt"].as_str().unwrap().ends_with('Z'));

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/policy",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["policy"], policy);
    assert!(body["updatedAt"].as_str().unwrap().ends_with('Z'));
}

#[tokio::test]
async fn grpc_gateway_policy_missing_database_row_is_status_json() {
    let (app, token, _db) = fixture_with_db().await;

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/policy",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 500);
    let body = body_json(resp).await;
    assert_eq!(body["code"], 2);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("acl policy not found")
    );
}

#[tokio::test]
async fn grpc_gateway_policy_persists_in_database_mode() {
    let (app, token, db) = fixture_with_db().await;
    let first = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:22"]}]}"#;
    let second = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:443"]}]}"#;

    for policy in [first, second] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::PUT,
                "/api/v1/policy",
                Some(&token),
                Body::from(serde_json::json!({ "policy": policy }).to_string()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 2);
    let latest = headscale_db::policies::get_latest(db.pool())
        .await
        .unwrap()
        .expect("latest policy");
    assert_eq!(latest.data, second);
}
