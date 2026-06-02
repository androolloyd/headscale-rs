//! grpc-gateway-compatible `/api/v1` route coverage.

#![cfg(all(feature = "admin", feature = "full"))]

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, header},
    response::Response,
};
use headscale_api::admin::{
    ApiKeyAdmin, ApiKeyMintRequest, PersistentApiKeyAdmin, PersistentMachineAdmin,
    PersistentPreauthAdmin, PersistentUserAdmin, WireMachineAdmin,
};
use headscale_api::grpc::upstream::{DatabaseHealthCheck, HeadscaleAdminService};
use headscale_api::grpc_gateway;
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::{
    AuthWaitOutcome, MachineRegistry, RegistrationCache, SshCheckBinding,
};
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

async fn fixture_with_wire_registry()
-> (Router, String, Arc<MachineRegistry>, headscale_db::Database) {
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
    let registry = Arc::new(MachineRegistry::new());
    let machines = Arc::new(WireMachineAdmin::new(registry.clone()));
    let service = HeadscaleAdminService::with_user_admin(
        users,
        api_keys,
        preauth,
        PolicyStore::new(),
        machines,
    )
    .with_database_pool(db.pool().clone())
    .with_policy_pool(db.pool().clone());
    (grpc_gateway::router(service), created.api_key, registry, db)
}

async fn fixture_with_registration_cache() -> (
    Router,
    String,
    Arc<RegistrationCache>,
    headscale_db::Database,
) {
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
    let registration_cache = Arc::new(RegistrationCache::new());
    let machines = Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new())));
    let service = HeadscaleAdminService::with_user_admin(
        users,
        api_keys,
        preauth,
        PolicyStore::new(),
        machines,
    )
    .with_database_pool(db.pool().clone())
    .with_policy_pool(db.pool().clone())
    .with_registration_cache(registration_cache.clone());
    (
        grpc_gateway::router(service),
        created.api_key,
        registration_cache,
        db,
    )
}

async fn fixture_with_db() -> (Router, String, headscale_db::Database) {
    let db = headscale_db::Database::in_memory()
        .await
        .expect("open in-memory db");
    db.migrate().await.expect("migrate");

    let (service, token) = service_for_db(&db, false).await;
    (grpc_gateway::router(service), token, db)
}

async fn fixture_with_persistent_machines() -> (Router, String, headscale_db::Database) {
    let db = headscale_db::Database::in_memory()
        .await
        .expect("open in-memory db");
    db.migrate().await.expect("migrate");

    let (service, token) = service_for_db(&db, true).await;
    (grpc_gateway::router(service), token, db)
}

async fn service_for_db(
    db: &headscale_db::Database,
    persistent_machines: bool,
) -> (HeadscaleAdminService, String) {
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    let api_keys = Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone()));
    let created = api_keys
        .mint(ApiKeyMintRequest { expiration: None })
        .await
        .expect("mint api key");
    let preauth = Arc::new(
        PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone()),
    );
    let machines: Arc<dyn headscale_api::admin::MachineAdmin> = if persistent_machines {
        Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone()))
    } else {
        Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new())))
    };
    let service = HeadscaleAdminService::with_user_admin(
        users,
        api_keys,
        preauth,
        PolicyStore::new(),
        machines,
    )
    .with_database_pool(db.pool().clone())
    .with_policy_pool(db.pool().clone());
    (service, created.api_key)
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
    req_with_content_type(method, uri, token, "application/json", body)
}

fn req_with_content_type(
    method: Method,
    uri: &str,
    token: Option<&str>,
    content_type: &'static str,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .header(header::CONTENT_TYPE, content_type)
        .body(body.into())
        .unwrap()
}

fn req_raw_auth(
    method: Method,
    uri: &str,
    authorization: Option<&str>,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

fn req_raw_auth_value(
    method: Method,
    uri: &str,
    authorization: HeaderValue,
    body: impl Into<Body>,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, authorization)
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

fn assert_security_headers(resp: &Response) {
    let headers = resp.headers();
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("frame-ancestors 'none'")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
}

async fn assert_status_json(
    resp: Response,
    expected_http_status: u16,
    expected_grpc_code: i64,
    message_fragment: &str,
    context: &str,
) {
    assert_eq!(
        resp.status().as_u16(),
        expected_http_status,
        "{context}: HTTP status"
    );
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "{context}: content-type"
    );
    let body = body_json(resp).await;
    let object = body
        .as_object()
        .unwrap_or_else(|| panic!("{context}: status body was not a JSON object: {body}"));
    assert_eq!(
        object.len(),
        3,
        "{context}: status body should only contain code/message/details: {body}"
    );
    assert_eq!(
        body["code"].as_i64(),
        Some(expected_grpc_code),
        "{context}: grpc code"
    );
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains(message_fragment),
        "{context}: message {:?} did not contain {:?}",
        body["message"],
        message_fragment
    );
    assert_eq!(body["details"], serde_json::json!([]), "{context}: details");
}

async fn assert_status_json_exact(
    resp: Response,
    expected_http_status: u16,
    expected_grpc_code: i64,
    expected_message: &str,
    context: &str,
) {
    assert_eq!(
        resp.status().as_u16(),
        expected_http_status,
        "{context}: HTTP status"
    );
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "{context}: content-type"
    );
    let body = body_json(resp).await;
    let object = body
        .as_object()
        .unwrap_or_else(|| panic!("{context}: status body was not a JSON object: {body}"));
    assert_eq!(
        object.len(),
        3,
        "{context}: status body should only contain code/message/details: {body}"
    );
    assert_eq!(
        body["code"].as_i64(),
        Some(expected_grpc_code),
        "{context}: grpc code"
    );
    assert_eq!(body["message"], expected_message, "{context}: message");
    assert_eq!(body["details"], serde_json::json!([]), "{context}: details");
}

fn swagger_param_signature(param: &Value) -> String {
    let name = param["name"].as_str().expect("parameter name");
    let location = param["in"].as_str().expect("parameter location");
    if let Some(reference) = param
        .get("schema")
        .and_then(|schema| schema.get("$ref"))
        .and_then(Value::as_str)
    {
        return format!("{name}:{location}:{reference}");
    }

    let kind = param["type"].as_str().expect("parameter type");
    match param.get("format").and_then(Value::as_str) {
        Some(format) => format!("{name}:{location}:{kind}:{format}"),
        None => format!("{name}:{location}:{kind}"),
    }
}

async fn assert_not_gateway_route_fallback(resp: Response, context: &str) {
    let status = resp.status();
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "{context}: content-type"
    );
    let body = body_json(resp).await;
    assert!(
        !(status.as_u16() == 404
            && body["code"].as_i64() == Some(5)
            && body["message"] == "unmatched route"),
        "{context}: advertised route fell through to unmatched-route fallback: {body}"
    );
    assert!(
        !(status.as_u16() == 501
            && body["code"].as_i64() == Some(12)
            && body["message"] == "Method Not Allowed"),
        "{context}: advertised method fell through to method-not-allowed fallback: {body}"
    );
}

async fn assert_plain_unauthorized_without_leak(resp: Response, forbidden: &[&str]) {
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/plain; charset=utf-8")
    );
    assert!(
        resp.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "headscale-go HTTP auth middleware does not emit WWW-Authenticate"
    );
    let body = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"Unauthorized");
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.len() < 100,
        "unauthorized body should be minimal: {body}"
    );
    for forbidden in forbidden {
        assert!(
            !body.contains(forbidden),
            "unauthorized response leaked protected value {forbidden}: {body}"
        );
    }
}

async fn assert_plain_unauthorized(resp: Response) {
    assert_plain_unauthorized_without_leak(resp, &[]).await;
}

#[tokio::test]
async fn apiauthenticationbypass_apiauthenticationbypasscurl() {
    let (app, token) = fixture().await;
    let users = ["user1", "user2", "user3", "testuser1", "testuser2"];

    for user in users {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/v1/user",
                Some(&token),
                Body::from(format!(r#"{{"name":"{user}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create {user}");
    }

    for authorization in [
        None,
        Some("InvalidToken"),
        Some("Bearer invalid-token-12345"),
    ] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                Method::GET,
                "/api/v1/user",
                authorization,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_plain_unauthorized_without_leak(resp, &users).await;
    }

    for authorization in [None, Some("Authorization: InvalidToken")] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                Method::GET,
                "/api/v1/user?name=testuser1",
                authorization,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_plain_unauthorized_without_leak(resp, &users).await;
    }

    let resp = app
        .clone()
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
    let returned = body["users"].as_array().expect("users");
    assert_eq!(returned.len(), users.len());
    for user in users {
        assert!(
            returned
                .iter()
                .any(|entry| entry["name"].as_str() == Some(user)),
            "authorized response should include {user}: {body}"
        );
    }

    let valid_header = format!("Bearer {token}");
    let resp = app
        .oneshot(req_raw_auth(
            Method::GET,
            "/api/v1/user?name=testuser1",
            Some(&valid_header),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["users"].as_array().expect("filtered users").len(), 1);
    assert_eq!(body["users"][0]["name"].as_str(), Some("testuser1"));
}

#[tokio::test]
async fn grpc_gateway_auth_failures_are_plain_unauthorized_before_parsers() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        authorization: Option<&'static str>,
        body: &'static str,
    }

    let (app, _token) = fixture().await;

    for case in [
        Case {
            name: "missing bearer on malformed JSON",
            method: Method::POST,
            uri: "/api/v1/user",
            authorization: None,
            body: "{",
        },
        Case {
            name: "malformed authorization scheme on malformed query",
            method: Method::GET,
            uri: "/api/v1/user?id=not-a-number",
            authorization: Some("Token definitely-invalid"),
            body: "",
        },
        Case {
            name: "bearer prefix without required space before malformed query",
            method: Method::GET,
            uri: "/api/v1/user?id=not-a-number",
            authorization: Some("Bearer"),
            body: "",
        },
        Case {
            name: "lowercase bearer prefix before malformed JSON",
            method: Method::POST,
            uri: "/api/v1/user",
            authorization: Some("bearer definitely-invalid"),
            body: "{",
        },
        Case {
            name: "invalid bearer on malformed path",
            method: Method::DELETE,
            uri: "/api/v1/user/not-a-number",
            authorization: Some("Bearer definitely-invalid"),
            body: "",
        },
        Case {
            name: "empty bearer token",
            method: Method::GET,
            uri: "/api/v1/health",
            authorization: Some("Bearer "),
            body: "",
        },
        Case {
            name: "missing bearer on body path route before body and path parsers",
            method: Method::POST,
            uri: "/api/v1/node/not-a-number/tags",
            authorization: None,
            body: "null",
        },
        Case {
            name: "invalid bearer on path query route before path and query parsers",
            method: Method::POST,
            uri: "/api/v1/node/not-a-number/expire?expiry.seconds=not-a-number",
            authorization: Some("Bearer definitely-invalid"),
            body: "",
        },
        Case {
            name: "malformed authorization scheme before delete apikey query parser",
            method: Method::DELETE,
            uri: "/api/v1/apikey/prefix?id=not-a-number",
            authorization: Some("Token definitely-invalid"),
            body: "",
        },
        Case {
            name: "missing bearer on policy route before body parser",
            method: Method::PUT,
            uri: "/api/v1/policy",
            authorization: None,
            body: "null",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                case.method,
                case.uri,
                case.authorization,
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "{}", case.name);
        assert_plain_unauthorized(resp).await;
    }
}

#[tokio::test]
async fn grpc_gateway_unauthenticated_user_list_does_not_leak_existing_users() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"alice","email":"alice@example.com"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    for authorization in [None, Some("Bearer definitely-invalid")] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                Method::GET,
                "/api/v1/user?name=alice",
                authorization,
                Body::empty(),
            ))
            .await
            .unwrap();

        assert_plain_unauthorized(resp).await;
    }
}

#[tokio::test]
async fn grpc_gateway_opaque_authorization_header_is_plain_unauthorized() {
    let (app, _token) = fixture().await;

    let resp = app
        .oneshot(req_raw_auth_value(
            Method::POST,
            "/api/v1/user",
            HeaderValue::from_bytes(b"Bearer \xfa").expect("opaque HTTP header value"),
            Body::from("{"),
        ))
        .await
        .unwrap();

    assert_plain_unauthorized(resp).await;
}

#[tokio::test]
async fn grpc_gateway_auth_route_auth_failures_are_plain_unauthorized_before_parsers() {
    struct Case {
        name: &'static str,
        uri: &'static str,
        authorization: Option<&'static str>,
        body: &'static str,
    }

    let (app, _token) = fixture().await;

    for case in [
        Case {
            name: "auth register missing bearer before malformed JSON",
            uri: "/api/v1/auth/register",
            authorization: None,
            body: "{",
        },
        Case {
            name: "auth approve malformed scheme before unknown body field",
            uri: "/api/v1/auth/approve",
            authorization: Some("Token definitely-invalid"),
            body: r#"{"authId":"abc","unknown":true}"#,
        },
        Case {
            name: "auth reject invalid bearer before auth id validation",
            uri: "/api/v1/auth/reject",
            authorization: Some("Bearer definitely-invalid"),
            body: r#"{"authId":"short"}"#,
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                Method::POST,
                case.uri,
                case.authorization,
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "{}", case.name);
        assert_plain_unauthorized(resp).await;
    }
}

#[tokio::test]
async fn grpc_gateway_current_head_shim_auth_preempts_parser_matrix() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        authorization: Option<&'static str>,
        body: &'static str,
    }

    let (app, _token) = fixture().await;

    for case in [
        Case {
            name: "preauth delete query parser",
            method: Method::DELETE,
            uri: "/api/v1/preauthkey?id=not-a-number",
            authorization: None,
            body: "",
        },
        Case {
            name: "debug node body parser",
            method: Method::POST,
            uri: "/api/v1/debug/node",
            authorization: Some("Token definitely-invalid"),
            body: r#"{"routes":[null]}"#,
        },
        Case {
            name: "backfill bool query parser with malformed body",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed=not-bool",
            authorization: Some("Bearer definitely-invalid"),
            body: "{",
        },
        Case {
            name: "apikey expire protojson parser",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            authorization: None,
            body: r#"{"id":"0x1"}"#,
        },
        Case {
            name: "approve routes path and body parsers",
            method: Method::POST,
            uri: "/api/v1/node/not-a-number/approve_routes",
            authorization: Some("Bearer definitely-invalid"),
            body: r#"{"nodeId":"also-bad","routes":[1]}"#,
        },
        Case {
            name: "auth approve protojson parser",
            method: Method::POST,
            uri: "/api/v1/auth/approve",
            authorization: Some("bearer definitely-invalid"),
            body: r#"{"authId":42}"#,
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req_raw_auth(
                case.method,
                case.uri,
                case.authorization,
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "{}", case.name);
        assert_plain_unauthorized(resp).await;
    }
}

#[tokio::test]
async fn grpc_gateway_health_missing_auth_returns_plain_unauthorized() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/health", None, Body::empty()))
        .await
        .unwrap();
    assert_security_headers(&resp);
    assert_plain_unauthorized(resp).await;

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
    assert_security_headers(&resp);
    let body = body_json(resp).await;
    assert_eq!(body["databaseConnectivity"], true);
}

#[tokio::test]
async fn grpc_gateway_health_bad_bearer_returns_plain_unauthorized() {
    let (app, _token) = fixture().await;

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/health",
            Some("definitely-invalid"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_plain_unauthorized(resp).await;
}

#[tokio::test]
async fn grpc_gateway_auth_runs_before_path_parser_errors() {
    let (app, _token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::DELETE,
            "/api/v1/user/not-a-uint64",
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_plain_unauthorized(resp).await;

    let resp = app
        .oneshot(req(
            Method::DELETE,
            "/api/v1/user/not-a-uint64",
            Some("definitely-invalid"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_plain_unauthorized(resp).await;
}

#[tokio::test]
async fn grpc_gateway_auth_runs_before_unmatched_api_routes() {
    let (app, _token) = fixture().await;

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/not-implemented-yet",
            None,
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_plain_unauthorized(resp).await;
}

#[tokio::test]
async fn grpc_gateway_routing_errors_are_status_json_after_auth() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
    }

    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::GET,
            "/api/v1/not-implemented-yet",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_status_json_exact(resp, 404, 5, "Not Found", "unmatched route").await;

    for case in [
        Case {
            name: "user id method mismatch",
            method: Method::GET,
            uri: "/api/v1/user/1",
        },
        Case {
            name: "health method mismatch",
            method: Method::DELETE,
            uri: "/api/v1/health",
        },
        Case {
            name: "policy method mismatch",
            method: Method::POST,
            uri: "/api/v1/policy",
        },
        Case {
            name: "node register method mismatch",
            method: Method::GET,
            uri: "/api/v1/node/register",
        },
        Case {
            name: "apikey method mismatch",
            method: Method::PUT,
            uri: "/api/v1/apikey",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(case.method, case.uri, Some(&token), Body::empty()))
            .await
            .unwrap();
        assert_status_json_exact(resp, 501, 12, "Method Not Allowed", case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_post_form_path_length_fallback_matches_current_upstream() {
    struct Case {
        name: &'static str,
        uri: &'static str,
        content_type: &'static str,
        body: &'static str,
        expected_http_status: u16,
        expected_grpc_code: Option<i64>,
        expected_message: Option<&'static str>,
    }

    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"form-fallback-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    for case in [
        Case {
            name: "form body becomes list-nodes query",
            uri: "/api/v1/node",
            content_type: "application/x-www-form-urlencoded",
            body: "user=form-fallback-user",
            expected_http_status: 200,
            expected_grpc_code: None,
            expected_message: None,
        },
        Case {
            name: "form body values precede URL query values",
            uri: "/api/v1/node?user=query-user",
            content_type: "application/x-www-form-urlencoded",
            body: "user=body-user",
            expected_http_status: 400,
            expected_grpc_code: Some(3),
            expected_message: Some(r#"too many values for field "user": body-user, query-user"#),
        },
        Case {
            name: "form body uses same nested scalar query parser",
            uri: "/api/v1/node",
            content_type: "application/x-www-form-urlencoded",
            body: "user.name=form-fallback-user",
            expected_http_status: 400,
            expected_grpc_code: Some(3),
            expected_message: Some(r#"invalid path: "user" is not a message"#),
        },
        Case {
            name: "form body rejects raw semicolon separator",
            uri: "/api/v1/node",
            content_type: "application/x-www-form-urlencoded",
            body: "user=form-fallback-user;ignored=true",
            expected_http_status: 400,
            expected_grpc_code: Some(3),
            expected_message: Some("invalid semicolon separator in query"),
        },
        Case {
            name: "JSON POST remains method mismatch",
            uri: "/api/v1/node",
            content_type: "application/json",
            body: "user=form-fallback-user",
            expected_http_status: 501,
            expected_grpc_code: Some(12),
            expected_message: Some("Method Not Allowed"),
        },
        Case {
            name: "form content type with parameters does not fallback",
            uri: "/api/v1/node",
            content_type: "application/x-www-form-urlencoded; charset=utf-8",
            body: "user=form-fallback-user",
            expected_http_status: 501,
            expected_grpc_code: Some(12),
            expected_message: Some("Method Not Allowed"),
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req_with_content_type(
                Method::POST,
                case.uri,
                Some(&token),
                case.content_type,
                Body::from(case.body),
            ))
            .await
            .unwrap();

        if let (Some(expected_grpc_code), Some(expected_message)) =
            (case.expected_grpc_code, case.expected_message)
        {
            assert_status_json_exact(
                resp,
                case.expected_http_status,
                expected_grpc_code,
                expected_message,
                case.name,
            )
            .await;
        } else {
            assert_eq!(
                resp.status().as_u16(),
                case.expected_http_status,
                "{}: HTTP status",
                case.name
            );
            let body = body_json(resp).await;
            assert_eq!(body["nodes"], serde_json::json!([]), "{}", case.name);
        }
    }
}

#[tokio::test]
async fn grpc_gateway_mounts_all_advertised_swagger_routes() {
    struct RouteCase {
        swagger_path: &'static str,
        concrete_path: &'static str,
        allowed_methods: &'static [&'static str],
        wrong_method: &'static str,
    }

    fn method(name: &str) -> Method {
        Method::from_bytes(name.as_bytes()).expect("test method is valid")
    }

    const SWAGGER: &str = include_str!("../src/tailscale_wire/assets/headscale.swagger.json");
    const ROUTES: &[RouteCase] = &[
        RouteCase {
            swagger_path: "/api/v1/apikey",
            concrete_path: "/api/v1/apikey",
            allowed_methods: &["GET", "POST"],
            wrong_method: "PUT",
        },
        RouteCase {
            swagger_path: "/api/v1/apikey/expire",
            concrete_path: "/api/v1/apikey/expire",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/apikey/{prefix}",
            concrete_path: "/api/v1/apikey/testprefix",
            allowed_methods: &["DELETE"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/auth/approve",
            concrete_path: "/api/v1/auth/approve",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/auth/register",
            concrete_path: "/api/v1/auth/register",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/auth/reject",
            concrete_path: "/api/v1/auth/reject",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/debug/node",
            concrete_path: "/api/v1/debug/node",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/health",
            concrete_path: "/api/v1/health",
            allowed_methods: &["GET"],
            wrong_method: "DELETE",
        },
        RouteCase {
            swagger_path: "/api/v1/node",
            concrete_path: "/api/v1/node",
            allowed_methods: &["GET"],
            wrong_method: "POST",
        },
        RouteCase {
            swagger_path: "/api/v1/node/backfillips",
            concrete_path: "/api/v1/node/backfillips",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/node/register",
            concrete_path: "/api/v1/node/register",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/node/{nodeId}",
            concrete_path: "/api/v1/node/1",
            allowed_methods: &["GET", "DELETE"],
            wrong_method: "POST",
        },
        RouteCase {
            swagger_path: "/api/v1/node/{nodeId}/approve_routes",
            concrete_path: "/api/v1/node/1/approve_routes",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/node/{nodeId}/expire",
            concrete_path: "/api/v1/node/1/expire",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/node/{nodeId}/rename/{newName}",
            concrete_path: "/api/v1/node/1/rename/new-name",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/node/{nodeId}/tags",
            concrete_path: "/api/v1/node/1/tags",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/policy",
            concrete_path: "/api/v1/policy",
            allowed_methods: &["GET", "PUT"],
            wrong_method: "POST",
        },
        RouteCase {
            swagger_path: "/api/v1/policy/check",
            concrete_path: "/api/v1/policy/check",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/preauthkey",
            concrete_path: "/api/v1/preauthkey",
            allowed_methods: &["GET", "POST", "DELETE"],
            wrong_method: "PUT",
        },
        RouteCase {
            swagger_path: "/api/v1/preauthkey/expire",
            concrete_path: "/api/v1/preauthkey/expire",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/user",
            concrete_path: "/api/v1/user",
            allowed_methods: &["GET", "POST"],
            wrong_method: "PUT",
        },
        RouteCase {
            swagger_path: "/api/v1/user/{id}",
            concrete_path: "/api/v1/user/1",
            allowed_methods: &["DELETE"],
            wrong_method: "GET",
        },
        RouteCase {
            swagger_path: "/api/v1/user/{oldId}/rename/{newName}",
            concrete_path: "/api/v1/user/1/rename/new-name",
            allowed_methods: &["POST"],
            wrong_method: "GET",
        },
    ];

    let swagger: Value = serde_json::from_str(SWAGGER).expect("swagger JSON parses");
    let paths = swagger["paths"].as_object().expect("swagger has paths");
    let advertised = paths
        .iter()
        .map(|(path, operations)| {
            let mut methods = operations
                .as_object()
                .expect("swagger path has operations")
                .keys()
                .filter(|method| matches!(method.as_str(), "delete" | "get" | "post" | "put"))
                .map(|method| method.to_ascii_uppercase())
                .collect::<Vec<_>>();
            methods.sort();
            (path.clone(), methods)
        })
        .collect::<BTreeMap<_, _>>();
    let expected = ROUTES
        .iter()
        .map(|route| {
            let mut methods = route
                .allowed_methods
                .iter()
                .map(|method| (*method).to_string())
                .collect::<Vec<_>>();
            methods.sort();
            (route.swagger_path.to_string(), methods)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(advertised, expected, "swagger route/method set drifted");

    let (app, token) = fixture().await;
    for route in ROUTES {
        for allowed in route.allowed_methods {
            let body = if *allowed == "GET" || *allowed == "DELETE" {
                Body::empty()
            } else {
                Body::from("{}")
            };
            let resp = app
                .clone()
                .oneshot(req(
                    method(allowed),
                    route.concrete_path,
                    Some(&token),
                    body,
                ))
                .await
                .unwrap();
            assert_not_gateway_route_fallback(resp, &format!("{} {allowed}", route.swagger_path))
                .await;
        }

        let resp = app
            .clone()
            .oneshot(req(
                method(route.wrong_method),
                route.concrete_path,
                Some(&token),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_status_json_exact(
            resp,
            501,
            12,
            "Method Not Allowed",
            &format!("{} wrong method", route.swagger_path),
        )
        .await;
    }

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/tailnet",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_status_json_exact(resp, 404, 5, "Not Found", "tailnet is not grpc-gateway").await;
}

#[test]
fn grpc_gateway_current_head_swagger_request_mapping_is_exact() {
    struct OperationCase {
        path: &'static str,
        method: &'static str,
        operation_id: &'static str,
        params: &'static [&'static str],
    }

    const OPERATIONS: &[OperationCase] = &[
        OperationCase {
            path: "/api/v1/apikey",
            method: "GET",
            operation_id: "HeadscaleService_ListApiKeys",
            params: &[],
        },
        OperationCase {
            path: "/api/v1/apikey",
            method: "POST",
            operation_id: "HeadscaleService_CreateApiKey",
            params: &["body:body:#/definitions/v1CreateApiKeyRequest"],
        },
        OperationCase {
            path: "/api/v1/apikey/expire",
            method: "POST",
            operation_id: "HeadscaleService_ExpireApiKey",
            params: &["body:body:#/definitions/v1ExpireApiKeyRequest"],
        },
        OperationCase {
            path: "/api/v1/apikey/{prefix}",
            method: "DELETE",
            operation_id: "HeadscaleService_DeleteApiKey",
            params: &["prefix:path:string", "id:query:string:uint64"],
        },
        OperationCase {
            path: "/api/v1/auth/approve",
            method: "POST",
            operation_id: "HeadscaleService_AuthApprove",
            params: &["body:body:#/definitions/v1AuthApproveRequest"],
        },
        OperationCase {
            path: "/api/v1/auth/register",
            method: "POST",
            operation_id: "HeadscaleService_AuthRegister",
            params: &["body:body:#/definitions/v1AuthRegisterRequest"],
        },
        OperationCase {
            path: "/api/v1/auth/reject",
            method: "POST",
            operation_id: "HeadscaleService_AuthReject",
            params: &["body:body:#/definitions/v1AuthRejectRequest"],
        },
        OperationCase {
            path: "/api/v1/debug/node",
            method: "POST",
            operation_id: "HeadscaleService_DebugCreateNode",
            params: &["body:body:#/definitions/v1DebugCreateNodeRequest"],
        },
        OperationCase {
            path: "/api/v1/health",
            method: "GET",
            operation_id: "HeadscaleService_Health",
            params: &[],
        },
        OperationCase {
            path: "/api/v1/node",
            method: "GET",
            operation_id: "HeadscaleService_ListNodes",
            params: &["user:query:string"],
        },
        OperationCase {
            path: "/api/v1/node/backfillips",
            method: "POST",
            operation_id: "HeadscaleService_BackfillNodeIPs",
            params: &["confirmed:query:boolean"],
        },
        OperationCase {
            path: "/api/v1/node/register",
            method: "POST",
            operation_id: "HeadscaleService_RegisterNode",
            params: &["user:query:string", "key:query:string"],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}",
            method: "DELETE",
            operation_id: "HeadscaleService_DeleteNode",
            params: &["nodeId:path:string:uint64"],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}",
            method: "GET",
            operation_id: "HeadscaleService_GetNode",
            params: &["nodeId:path:string:uint64"],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}/approve_routes",
            method: "POST",
            operation_id: "HeadscaleService_SetApprovedRoutes",
            params: &[
                "nodeId:path:string:uint64",
                "body:body:#/definitions/HeadscaleServiceSetApprovedRoutesBody",
            ],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}/expire",
            method: "POST",
            operation_id: "HeadscaleService_ExpireNode",
            params: &[
                "nodeId:path:string:uint64",
                "expiry:query:string:date-time",
                "disableExpiry:query:boolean",
            ],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}/rename/{newName}",
            method: "POST",
            operation_id: "HeadscaleService_RenameNode",
            params: &["nodeId:path:string:uint64", "newName:path:string"],
        },
        OperationCase {
            path: "/api/v1/node/{nodeId}/tags",
            method: "POST",
            operation_id: "HeadscaleService_SetTags",
            params: &[
                "nodeId:path:string:uint64",
                "body:body:#/definitions/HeadscaleServiceSetTagsBody",
            ],
        },
        OperationCase {
            path: "/api/v1/policy",
            method: "GET",
            operation_id: "HeadscaleService_GetPolicy",
            params: &[],
        },
        OperationCase {
            path: "/api/v1/policy",
            method: "PUT",
            operation_id: "HeadscaleService_SetPolicy",
            params: &["body:body:#/definitions/v1SetPolicyRequest"],
        },
        OperationCase {
            path: "/api/v1/policy/check",
            method: "POST",
            operation_id: "HeadscaleService_CheckPolicy",
            params: &["body:body:#/definitions/v1CheckPolicyRequest"],
        },
        OperationCase {
            path: "/api/v1/preauthkey",
            method: "DELETE",
            operation_id: "HeadscaleService_DeletePreAuthKey",
            params: &["id:query:string:uint64"],
        },
        OperationCase {
            path: "/api/v1/preauthkey",
            method: "GET",
            operation_id: "HeadscaleService_ListPreAuthKeys",
            params: &[],
        },
        OperationCase {
            path: "/api/v1/preauthkey",
            method: "POST",
            operation_id: "HeadscaleService_CreatePreAuthKey",
            params: &["body:body:#/definitions/v1CreatePreAuthKeyRequest"],
        },
        OperationCase {
            path: "/api/v1/preauthkey/expire",
            method: "POST",
            operation_id: "HeadscaleService_ExpirePreAuthKey",
            params: &["body:body:#/definitions/v1ExpirePreAuthKeyRequest"],
        },
        OperationCase {
            path: "/api/v1/user",
            method: "GET",
            operation_id: "HeadscaleService_ListUsers",
            params: &[
                "id:query:string:uint64",
                "name:query:string",
                "email:query:string",
            ],
        },
        OperationCase {
            path: "/api/v1/user",
            method: "POST",
            operation_id: "HeadscaleService_CreateUser",
            params: &["body:body:#/definitions/v1CreateUserRequest"],
        },
        OperationCase {
            path: "/api/v1/user/{id}",
            method: "DELETE",
            operation_id: "HeadscaleService_DeleteUser",
            params: &["id:path:string:uint64"],
        },
        OperationCase {
            path: "/api/v1/user/{oldId}/rename/{newName}",
            method: "POST",
            operation_id: "HeadscaleService_RenameUser",
            params: &["oldId:path:string:uint64", "newName:path:string"],
        },
    ];

    const SWAGGER: &str = include_str!("../src/tailscale_wire/assets/headscale.swagger.json");
    let swagger: Value = serde_json::from_str(SWAGGER).expect("swagger JSON parses");
    let paths = swagger["paths"].as_object().expect("swagger has paths");

    let mut actual = BTreeMap::<(String, String), (String, Vec<String>)>::new();
    for (path, operations) in paths {
        let operations = operations.as_object().expect("swagger path has operations");
        for method in ["delete", "get", "post", "put"] {
            let Some(operation) = operations.get(method) else {
                continue;
            };
            let operation_id = operation["operationId"]
                .as_str()
                .expect("operation has operationId")
                .to_string();
            let params = operation
                .get("parameters")
                .and_then(Value::as_array)
                .map(|params| {
                    params
                        .iter()
                        .map(swagger_param_signature)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            actual.insert(
                (path.clone(), method.to_ascii_uppercase()),
                (operation_id, params),
            );
        }
    }

    let expected = OPERATIONS
        .iter()
        .map(|case| {
            (
                (case.path.to_string(), case.method.to_string()),
                (
                    case.operation_id.to_string(),
                    case.params
                        .iter()
                        .map(|param| (*param).to_string())
                        .collect(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual, expected,
        "current-head grpc-gateway request mapping drifted"
    );
}

#[tokio::test]
async fn grpc_gateway_rejects_non_upstream_octra_api_routes() {
    let (app, token) = fixture().await;

    for (name, method, uri, body) in [
        (
            "legacy plural nodes list",
            Method::GET,
            "/api/v1/nodes",
            Body::empty(),
        ),
        (
            "legacy plural nodes register",
            Method::POST,
            "/api/v1/nodes",
            Body::from(r#"{"name":"octra-node"}"#),
        ),
        (
            "legacy register alias",
            Method::POST,
            "/api/v1/register",
            Body::from(r#"{"name":"octra-node"}"#),
        ),
        (
            "legacy node heartbeat",
            Method::POST,
            "/api/v1/nodes/1/heartbeat",
            Body::empty(),
        ),
        (
            "legacy status",
            Method::GET,
            "/api/v1/status",
            Body::empty(),
        ),
        (
            "legacy balance",
            Method::GET,
            "/api/v1/balance/did:example:alice",
            Body::empty(),
        ),
        (
            "legacy transfer",
            Method::POST,
            "/api/v1/transfer",
            Body::from(r#"{"amount":1}"#),
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(req(method, uri, Some(&token), body))
            .await
            .unwrap();
        assert_status_json_exact(resp, 404, 5, "Not Found", name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_authenticated_server_errors_are_status_json_exact() {
    enum Fixture {
        EmptyPolicyDb,
        FailingHealth,
    }

    struct Case {
        name: &'static str,
        fixture: Fixture,
        method: Method,
        uri: &'static str,
        body: &'static str,
        expected_http_status: u16,
        expected_grpc_code: i64,
        expected_message: &'static str,
    }

    for case in [
        Case {
            name: "health database failure",
            fixture: Fixture::FailingHealth,
            method: Method::GET,
            uri: "/api/v1/health",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "pinging database: forced offline",
        },
        Case {
            name: "policy missing database row",
            fixture: Fixture::EmptyPolicyDb,
            method: Method::GET,
            uri: "/api/v1/policy",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "loading ACL from database: acl policy not found",
        },
    ] {
        let (app, token) = match case.fixture {
            Fixture::EmptyPolicyDb => {
                let (app, token, _db) = fixture_with_db().await;
                (app, token)
            }
            Fixture::FailingHealth => fixture_with_failing_health().await,
        };

        let resp = app
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(
            resp,
            case.expected_http_status,
            case.expected_grpc_code,
            case.expected_message,
            case.name,
        )
        .await;
    }
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
async fn grpc_gateway_malformed_json_failures_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        message_fragment: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "create user body",
            method: Method::POST,
            uri: "/api/v1/user",
            body: "{",
            message_fragment: "EOF while parsing",
        },
        Case {
            name: "whole-message null",
            method: Method::POST,
            uri: "/api/v1/user",
            body: "null",
            message_fragment: "unexpected token null",
        },
        Case {
            name: "whole-message array",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: "[]",
            message_fragment: "unexpected token [",
        },
        Case {
            name: "set policy body",
            method: Method::PUT,
            uri: "/api/v1/policy",
            body: r#"{"policy":"#,
            message_fragment: "EOF while parsing",
        },
        Case {
            name: "debug node body",
            method: Method::POST,
            uri: "/api/v1/debug/node",
            body: r#"{"user":"node-user","routes":["10.0.0.0/24",]}"#,
            message_fragment: "trailing comma",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_body_unknown_fields_are_discarded_like_grpc_gateway() {
    let (app, token) = fixture().await;

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"unknown-ok","unknown":1}"#),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["name"], "unknown-ok");
}

#[tokio::test]
async fn grpc_gateway_body_null_fields_are_absent_like_protojson() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(
                r#"{"name":"null-defaults","displayName":null,"display_name":"Alias Name","email":null,"pictureUrl":null}"#,
            ),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["name"], "null-defaults");
    assert_eq!(body["user"]["displayName"], "Alias Name");
    assert_eq!(body["user"]["email"], "");
    assert_eq!(body["user"]["profilePicUrl"], "");

    let user_id = body["user"]["id"]
        .as_str()
        .expect("created user id")
        .to_string();
    let create_preauth_body = format!(
        r#"{{"user":"{user_id}","reusable":null,"ephemeral":null,"expiration":null,"aclTags":null}}"#
    );
    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/preauthkey",
            Some(&token),
            Body::from(create_preauth_body),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["preAuthKey"]["user"]["id"], user_id.as_str());
    assert_eq!(body["preAuthKey"]["reusable"], false);
    assert_eq!(body["preAuthKey"]["ephemeral"], false);
    assert_eq!(body["preAuthKey"]["aclTags"], serde_json::json!([]));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/preauthkey/expire",
            Some(&token),
            Body::from(r#"{"id":null}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "null uint64 body field defaults to zero"
    );
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/apikey/expire",
            Some(&token),
            Body::from(r#"{"prefix":null}"#),
        ))
        .await
        .unwrap();
    assert_status_json_exact(
        resp,
        400,
        3,
        "must provide id or prefix",
        "null string body field defaults to empty",
    )
    .await;

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/approve",
            Some(&token),
            Body::from(r#"{"authId":null}"#),
        ))
        .await
        .unwrap();
    assert_status_json_exact(
        resp,
        400,
        3,
        r#"invalid auth_id: auth ID has invalid prefix: expected prefix "hskey-authreq-""#,
        "null string alias body field defaults to empty",
    )
    .await;
}

#[tokio::test]
async fn grpc_gateway_body_duplicate_fields_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        message_fragment: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "create user duplicate protojson field",
            method: Method::POST,
            uri: "/api/v1/user",
            body: r#"{"name":"alice","name":"bob"}"#,
            message_fragment: r#"duplicate field "name""#,
        },
        Case {
            name: "preauth json and proto field aliases conflict",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"aclTags":[],"acl_tags":[]}"#,
            message_fragment: "duplicate field",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_remaining_parser_failures_are_status_json_exact() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        expected_message: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "auth register json and proto field aliases conflict",
            method: Method::POST,
            uri: "/api/v1/auth/register",
            body: r#"{"user":"alice","authId":"a","auth_id":"b"}"#,
            expected_message: r#"duplicate field "auth_id""#,
        },
        Case {
            name: "auth reject numeric auth id",
            method: Method::POST,
            uri: "/api/v1/auth/reject",
            body: r#"{"authId":42}"#,
            expected_message: "invalid value for string field authId: 42",
        },
        Case {
            name: "set policy numeric body field",
            method: Method::PUT,
            uri: "/api/v1/policy",
            body: r#"{"policy":1}"#,
            expected_message: "invalid value for string field policy: 1",
        },
        Case {
            name: "register node duplicate key query field",
            method: Method::POST,
            uri: "/api/v1/node/register?user=alice&key=one&key=two",
            body: "",
            expected_message: r#"too many values for field "key": one, two"#,
        },
        Case {
            name: "register node nested key query path",
            method: Method::POST,
            uri: "/api/v1/node/register?key.foo=1",
            body: "",
            expected_message: r#"invalid path: "key" is not a message"#,
        },
        Case {
            name: "delete api key invalid id query field",
            method: Method::DELETE,
            uri: "/api/v1/apikey/prefix?id=not-a-number",
            body: "",
            expected_message: r#"parsing field "id": strconv.ParseUint: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "timestamp nanos query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry.nanos=not-a-number",
            body: "",
            expected_message: r#"parsing field "nanos": strconv.ParseInt: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "timestamp duplicate nanos query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry.nanos=1&expiry.nanos=2",
            body: "",
            expected_message: r#"too many values for field "nanos": 1, 2"#,
        },
        Case {
            name: "rename user old id path parameter",
            method: Method::POST,
            uri: "/api/v1/user/not-a-number/rename/new-name",
            body: "",
            expected_message: r#"type mismatch, parameter: old_id, error: strconv.ParseUint: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "expire node path parameter preempts query parser",
            method: Method::POST,
            uri: "/api/v1/node/not-a-number/expire?expiry.seconds=not-a-number",
            body: "",
            expected_message: r#"type mismatch, parameter: node_id, error: strconv.ParseUint: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "delete api key duplicate id query field",
            method: Method::DELETE,
            uri: "/api/v1/apikey/prefix?id=1&id=2",
            body: "",
            expected_message: r#"too many values for field "id": 1, 2"#,
        },
        Case {
            name: "empty bool query field",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed=",
            body: "",
            expected_message: r#"parsing field "confirmed": strconv.ParseBool: parsing "": invalid syntax"#,
        },
        Case {
            name: "nested string query path on scalar",
            method: Method::GET,
            uri: "/api/v1/node?user.name=alice",
            body: "",
            expected_message: r#"invalid path: "user" is not a message"#,
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(resp, 400, 3, case.expected_message, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_body_decoders_run_before_path_parsers_for_body_routes() {
    struct Case {
        name: &'static str,
        uri: &'static str,
        body: &'static str,
        expected_message: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "set tags whole-message null preempts node id path",
            uri: "/api/v1/node/not-a-number/tags",
            body: "null",
            expected_message: "syntax error (line 1:1): unexpected token null",
        },
        Case {
            name: "approve routes whole-message array preempts node id path",
            uri: "/api/v1/node/not-a-number/approve_routes",
            body: "[]",
            expected_message: "syntax error (line 1:1): unexpected token [",
        },
        Case {
            name: "set tags repeated field parser preempts node id path",
            uri: "/api/v1/node/not-a-number/tags",
            body: r#"{"tags":"tag:server"}"#,
            expected_message: r#"syntax error (line 1:1): unexpected token "tag:server""#,
        },
        Case {
            name: "approve routes repeated element parser preempts node id path",
            uri: "/api/v1/node/not-a-number/approve_routes",
            body: r#"{"routes":[null]}"#,
            expected_message: "invalid value for string field routes: null",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(resp, 400, 3, case.expected_message, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_current_head_body_query_parser_matrix_is_exact() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        expected_http_status: u16,
        expected_grpc_code: i64,
        expected_message: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "set tags body nodeId parser preempts service",
            method: Method::POST,
            uri: "/api/v1/node/404/tags",
            body: r#"{"nodeId":"0x1","tags":["tag:server"]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: r#"invalid value for uint64 field nodeId: "0x1""#,
        },
        Case {
            name: "approve routes body node_id parser preempts service",
            method: Method::POST,
            uri: "/api/v1/node/404/approve_routes",
            body: r#"{"node_id":-1,"routes":[]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "invalid value for uint64 field nodeId: -1",
        },
        Case {
            name: "approve routes body path field aliases conflict",
            method: Method::POST,
            uri: "/api/v1/node/404/approve_routes",
            body: r#"{"nodeId":"1","node_id":"2","routes":[]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: r#"duplicate field "node_id""#,
        },
        Case {
            name: "backfill no-body route ignores malformed JSON body",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed=false",
            body: "{",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "not confirmed, aborting",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(
            resp,
            case.expected_http_status,
            case.expected_grpc_code,
            case.expected_message,
            case.name,
        )
        .await;
    }
}

#[tokio::test]
async fn grpc_gateway_query_parser_failures_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        message_fragment: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "uint64 query field",
            method: Method::GET,
            uri: "/api/v1/user?id=not-a-number",
            message_fragment: r#"parsing field "id": strconv.ParseUint: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "query percent encoding",
            method: Method::GET,
            uri: "/api/v1/user?name=%ZZ",
            message_fragment: r#"invalid URL escape "%ZZ""#,
        },
        Case {
            name: "query semicolon separator",
            method: Method::GET,
            uri: "/api/v1/node?user=alice;ignored=bob",
            message_fragment: "invalid semicolon separator in query",
        },
        Case {
            name: "duplicate uint64 query field",
            method: Method::GET,
            uri: "/api/v1/user?id=1&id=2",
            message_fragment: r#"too many values for field "id": 1, 2"#,
        },
        Case {
            name: "duplicate string query field",
            method: Method::GET,
            uri: "/api/v1/node?user=alice&user=bob",
            message_fragment: r#"too many values for field "user": alice, bob"#,
        },
        Case {
            name: "empty uint64 query field",
            method: Method::DELETE,
            uri: "/api/v1/preauthkey?id=",
            message_fragment: r#"parsing field "id": strconv.ParseUint: parsing "": invalid syntax"#,
        },
        Case {
            name: "bool query field",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed=not-bool",
            message_fragment: r#"parsing field "confirmed": strconv.ParseBool: parsing "not-bool": invalid syntax"#,
        },
        Case {
            name: "timestamp seconds query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry.seconds=not-a-number",
            message_fragment: r#"parsing field "seconds": strconv.ParseInt: parsing "not-a-number": invalid syntax"#,
        },
        Case {
            name: "nested timestamp seconds query path on scalar",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry.seconds.foo=1",
            message_fragment: r#"invalid path: "seconds" is not a message"#,
        },
        Case {
            name: "timestamp root query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry=not-a-date",
            message_fragment: r#"parsing field "expiry": parsing time "not-a-date" as "2006-01-02T15:04:05.999999999Z07:00": cannot parse "not-a-date" as "2006""#,
        },
        Case {
            name: "timestamp root query underflow",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry=0000-01-01T00%3A00%3A00.00Z",
            message_fragment: r#"parsing field "expiry": 0000-01-01T00:00:00.00Z before 0001-01-01"#,
        },
        Case {
            name: "timestamp duplicate root query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry=2030-01-02T03%3A04%3A05Z&expiry=2031-01-02T03%3A04%3A05Z",
            message_fragment: r#"too many values for field "expiry": 2030-01-02T03:04:05Z, 2031-01-02T03:04:05Z"#,
        },
        Case {
            name: "timestamp bracket query field",
            method: Method::POST,
            uri: "/api/v1/node/1/expire?expiry%5Bseconds%5D=1",
            message_fragment: r#"too many values for field "expiry": seconds, 1"#,
        },
        Case {
            name: "nested uint64 query path on scalar",
            method: Method::GET,
            uri: "/api/v1/user?id.foo=1",
            message_fragment: r#"invalid path: "id" is not a message"#,
        },
        Case {
            name: "nested delete id query path on scalar",
            method: Method::DELETE,
            uri: "/api/v1/preauthkey?id.foo=1",
            message_fragment: r#"invalid path: "id" is not a message"#,
        },
        Case {
            name: "nested bool query path on scalar",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed.foo=true",
            message_fragment: r#"invalid path: "confirmed" is not a message"#,
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(case.method, case.uri, Some(&token), Body::empty()))
            .await
            .unwrap();
        assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_query_unknown_fields_are_discarded_like_grpc_gateway() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"query-unknown-ok"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/user?name=query-unknown-ok&unknown=true&unknown.path=ignored",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let users = body["users"].as_array().expect("users array");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["name"], "query-unknown-ok");
}

#[tokio::test]
async fn grpc_gateway_query_parser_accepts_go_bool_forms() {
    let (app, token) = fixture().await;

    for value in ["1", "t", "TRUE"] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                &format!("/api/v1/node/backfillips?confirmed={value}"),
                Some(&token),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "confirmed={value}");
        let body = body_json(resp).await;
        assert_eq!(body["changes"], serde_json::json!([]), "confirmed={value}");
    }

    for value in ["0", "F", "False"] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                &format!("/api/v1/node/backfillips?confirmed={value}"),
                Some(&token),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 500, "confirmed={value}");
        let body = body_json(resp).await;
        assert_ne!(
            body["code"],
            serde_json::json!(3),
            "confirmed={value} should parse as a Go bool before handler validation"
        );
    }
}

#[tokio::test]
async fn grpc_gateway_body_scalar_type_failures_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        message_fragment: &'static str,
        exact_message: Option<&'static str>,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "base-prefixed body uint64",
            method: Method::POST,
            uri: "/api/v1/preauthkey/expire",
            body: r#"{"id":"0x1"}"#,
            message_fragment: r#"invalid value for uint64 field id: "0x1""#,
            exact_message: None,
        },
        Case {
            name: "object timestamp body field",
            method: Method::POST,
            uri: "/api/v1/apikey",
            body: r#"{"expiration":{"seconds":4102444800}}"#,
            message_fragment: "unexpected token { for timestamp field expiration",
            exact_message: None,
        },
        Case {
            name: "timestamp body underflow",
            method: Method::POST,
            uri: "/api/v1/apikey",
            body: r#"{"expiration":"0001-01-01T00:00:00+01:00"}"#,
            message_fragment: r#"google.protobuf.Timestamp value out of range: "0001-01-01T00:00:00+01:00""#,
            exact_message: None,
        },
        Case {
            name: "string bool body field",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"reusable":"true"}"#,
            message_fragment: r#"invalid value for bool field reusable: "true""#,
            exact_message: None,
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        if let Some(expected_message) = case.exact_message {
            assert_status_json_exact(resp, 400, 3, expected_message, case.name).await;
        } else {
            assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
        }
    }
}

#[tokio::test]
async fn grpc_gateway_repeated_string_body_failures_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        message_fragment: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "non-array node tags field",
            method: Method::POST,
            uri: "/api/v1/node/1/tags",
            body: r#"{"tags":"tag:server"}"#,
            message_fragment: r#"unexpected token "tag:server""#,
        },
        Case {
            name: "numeric node tags element",
            method: Method::POST,
            uri: "/api/v1/node/1/tags",
            body: r#"{"tags":[1]}"#,
            message_fragment: "invalid value for string field tags: 1",
        },
        Case {
            name: "null route element",
            method: Method::POST,
            uri: "/api/v1/debug/node",
            body: r#"{"user":"alice","key":"abcdefghijklmnopqrstuvwx","routes":[null]}"#,
            message_fragment: "invalid value for string field routes: null",
        },
        Case {
            name: "object preauth acl tags field",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"aclTags":{}}"#,
            message_fragment: "unexpected token {",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_path_parser_failures_are_status_json() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: Body,
        message_fragment: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "user id decimal syntax",
            method: Method::DELETE,
            uri: "/api/v1/user/not-a-number",
            body: Body::empty(),
            message_fragment: "type mismatch, parameter: id",
        },
        Case {
            name: "node id hex syntax",
            method: Method::GET,
            uri: "/api/v1/node/0xzz",
            body: Body::empty(),
            message_fragment: r#"strconv.ParseUint: parsing "0xzz": invalid syntax"#,
        },
        Case {
            name: "node id uint64 overflow",
            method: Method::POST,
            uri: "/api/v1/node/18446744073709551616/tags",
            body: Body::from("{}"),
            message_fragment: "value out of range",
        },
        Case {
            name: "rename node id parameter name",
            method: Method::POST,
            uri: "/api/v1/node/not-a-number/rename/new-name",
            body: Body::empty(),
            message_fragment: "type mismatch, parameter: node_id",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(case.method, case.uri, Some(&token), case.body))
            .await
            .unwrap();
        assert_status_json(resp, 400, 3, case.message_fragment, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_path_uint64_accepts_go_base0_literals() {
    let (app, token) = fixture().await;

    for (name, expected_id, path_literal) in [
        ("hex-path-user", "1", "0x1"),
        ("binary-path-user", "2", "0b10"),
        ("explicit-octal-path-user", "3", "0o3"),
        ("legacy-octal-path-user", "4", "04"),
        ("underscore-path-user", "5", "0b1_01"),
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/v1/user",
                Some(&token),
                Body::from(format!(r#"{{"name":"{name}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "create {name}");
        let body = body_json(resp).await;
        assert_eq!(body["user"]["id"], expected_id, "create {name}");

        let resp = app
            .clone()
            .oneshot(req(
                Method::DELETE,
                &format!("/api/v1/user/{path_literal}"),
                Some(&token),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "delete {name} via {path_literal}");
        assert_eq!(
            body_json(resp).await,
            serde_json::json!({}),
            "delete {name} via {path_literal}"
        );
    }
}

#[tokio::test]
async fn grpc_gateway_remaining_route_status_failures_are_status_json_exact() {
    struct Case {
        name: &'static str,
        method: Method,
        uri: &'static str,
        body: &'static str,
        expected_http_status: u16,
        expected_grpc_code: i64,
        expected_message: &'static str,
    }

    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"status-dupe"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    for case in [
        Case {
            name: "create duplicate user",
            method: Method::POST,
            uri: "/api/v1/user",
            body: r#"{"name":"status-dupe"}"#,
            expected_http_status: 500,
            expected_grpc_code: 13,
            expected_message: "creating user: creating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
        },
        Case {
            name: "delete missing user",
            method: Method::DELETE,
            uri: "/api/v1/user/404",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "user not found",
        },
        Case {
            name: "create preauth key missing user",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"user":"404"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "user not found",
        },
        Case {
            name: "create preauth key missing owner or tags",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: "{}",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "auth-key must be either tagged or owned by user",
        },
        Case {
            name: "create preauth key invalid tag",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"aclTags":["tag:Bad"]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "tag should be lowercase",
        },
        Case {
            name: "create preauth key tag with space",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"aclTags":["tag:bad tag"]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "tags must not contain spaces",
        },
        Case {
            name: "expire api key missing selector",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: "{}",
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "must provide id or prefix",
        },
        Case {
            name: "expire api key missing id",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: r#"{"id":"999"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "api key not found",
        },
        Case {
            name: "expire api key missing prefix",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: r#"{"prefix":"hskey-api-abcdefghijkl-***"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "api key not found",
        },
        Case {
            name: "expire api key prefix too short",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: r#"{"prefix":"hskey-api-short"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "failed to parse ApiKey: prefix too short",
        },
        Case {
            name: "delete api key conflicting selectors",
            method: Method::DELETE,
            uri: "/api/v1/apikey/prefix?id=1",
            body: "",
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "provide either id or prefix, not both",
        },
        Case {
            name: "delete api key missing prefix",
            method: Method::DELETE,
            uri: "/api/v1/apikey/hskey-api-abcdefghijkl-***",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "api key not found",
        },
        Case {
            name: "delete api key prefix invalid characters",
            method: Method::DELETE,
            uri: "/api/v1/apikey/hskey-api-abc!efghijkl-***",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "failed to parse ApiKey: prefix contains invalid characters",
        },
        Case {
            name: "list nodes missing user",
            method: Method::GET,
            uri: "/api/v1/node?user=carol",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "user not found",
        },
        Case {
            name: "get missing node",
            method: Method::GET,
            uri: "/api/v1/node/404",
            body: "",
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "node not found",
        },
        Case {
            name: "set empty node tags",
            method: Method::POST,
            uri: "/api/v1/node/404/tags",
            body: r#"{"tags":[]}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "cannot remove all tags from a node - tagged nodes must have at least one tag",
        },
        Case {
            name: "backfill node ips not confirmed",
            method: Method::POST,
            uri: "/api/v1/node/backfillips?confirmed=false",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "not confirmed, aborting",
        },
        Case {
            name: "register node missing user",
            method: Method::POST,
            uri: "/api/v1/node/register?user=missing&key=hskey-authreq-statusregister1234567890",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "looking up user: user not found",
        },
        Case {
            name: "register node missing cache entry",
            method: Method::POST,
            uri: "/api/v1/node/register?user=status-dupe&key=hskey-authreq-statusregister1234567890",
            body: "",
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "node not found in registration cache",
        },
        Case {
            name: "auth register missing user",
            method: Method::POST,
            uri: "/api/v1/auth/register",
            body: r#"{"user":"missing","authId":"hskey-authreq-statusregister1234567890"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "looking up user: user not found",
        },
        Case {
            name: "auth register missing cache entry",
            method: Method::POST,
            uri: "/api/v1/auth/register",
            body: r#"{"user":"status-dupe","authId":"hskey-authreq-statusregister1234567890"}"#,
            expected_http_status: 500,
            expected_grpc_code: 2,
            expected_message: "node not found in registration cache",
        },
        Case {
            name: "auth approve no pending session",
            method: Method::POST,
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":"hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "no pending auth session for auth_id hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa",
        },
        Case {
            name: "auth reject no pending session",
            method: Method::POST,
            uri: "/api/v1/auth/reject",
            body: r#"{"authId":"hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb"}"#,
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "no pending auth session for auth_id hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb",
        },
        Case {
            name: "auth reject invalid prefixed auth id",
            method: Method::POST,
            uri: "/api/v1/auth/reject",
            body: r#"{"authId":"hskey-authreq-short"}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 19",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                case.method,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(
            resp,
            case.expected_http_status,
            case.expected_grpc_code,
            case.expected_message,
            case.name,
        )
        .await;
    }
}

#[tokio::test]
async fn grpc_gateway_preauth_missing_ids_are_noop_success() {
    let (app, token) = fixture().await;

    for (name, method, uri, body) in [
        (
            "expire preauth key missing id",
            Method::POST,
            "/api/v1/preauthkey/expire",
            Body::from(r#"{"id":"999"}"#),
        ),
        (
            "delete preauth key missing id",
            Method::DELETE,
            "/api/v1/preauthkey?id=999",
            Body::empty(),
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(req(method, uri, Some(&token), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{name}");
        assert_eq!(body_json(resp).await, serde_json::json!({}), "{name}");
    }
}

#[tokio::test]
async fn grpc_gateway_user_delete_non_empty_status_json() {
    let (app, token, _registry, _db) = fixture_with_wire_registry().await;
    let registration_key = "zyxwvutsrqponmlkjihgfedc";

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"owned-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);
    let body = body_json(created_user).await;
    let user_id = body["user"]["id"].as_str().expect("user id");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/debug/node",
            Some(&token),
            Body::from(format!(
                r#"{{"user":"owned-user","key":"hskey-authreq-{registration_key}","name":"owned-node"}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/register?user=owned-user&key=hskey-authreq-{registration_key}"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .oneshot(req(
            Method::DELETE,
            &format!("/api/v1/user/{user_id}"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_status_json_exact(
        resp,
        500,
        2,
        "user not empty: node(s) found",
        "delete user with owned node",
    )
    .await;
}

#[tokio::test]
async fn grpc_gateway_user_rename_raw_errors_are_status_json() {
    let (app, token) = fixture().await;

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"rename-source"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);
    let body = body_json(created_user).await;
    let source_id = body["user"]["id"].as_str().expect("source id");

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"rename-target"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);

    for (name, uri, expected_message) in [
        (
            "rename missing user",
            "/api/v1/user/404/rename/new-name".to_string(),
            "user not found",
        ),
        (
            "rename duplicate user",
            format!("/api/v1/user/{source_id}/rename/rename-target"),
            "updating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(req(Method::POST, &uri, Some(&token), Body::empty()))
            .await
            .unwrap();
        assert_status_json_exact(resp, 500, 2, expected_message, name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_auth_register_invalid_auth_ids_match_upstream_unknown() {
    let (app, token) = fixture().await;

    for (name, body, expected_message) in [
        (
            "auth register bare short authId",
            r#"{"user":"alice","authId":"short"}"#,
            r#"auth ID has invalid prefix: expected prefix "hskey-authreq-""#,
        ),
        (
            "auth register prefixed short authId",
            r#"{"user":"alice","authId":"hskey-authreq-short"}"#,
            "auth ID has invalid length: expected 38, got 19",
        ),
        (
            "auth register prefixed long authId",
            r#"{"user":"alice","authId":"hskey-authreq-abcdefghijklmnopqrstuvwxy"}"#,
            "auth ID has invalid length: expected 38, got 39",
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/v1/auth/register",
                Some(&token),
                Body::from(body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(resp, 500, 2, expected_message, name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_auth_approve_reject_malformed_auth_ids_are_exact() {
    struct Case {
        name: &'static str,
        uri: &'static str,
        body: &'static str,
        expected_message: &'static str,
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "auth approve missing auth id",
            uri: "/api/v1/auth/approve",
            body: "{}",
            expected_message: r#"invalid auth_id: auth ID has invalid prefix: expected prefix "hskey-authreq-""#,
        },
        Case {
            name: "auth approve bare auth id",
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":"abcdefghijklmnopqrstuvwx"}"#,
            expected_message: r#"invalid auth_id: auth ID has invalid prefix: expected prefix "hskey-authreq-""#,
        },
        Case {
            name: "auth reject missing auth id",
            uri: "/api/v1/auth/reject",
            body: "{}",
            expected_message: r#"invalid auth_id: auth ID has invalid prefix: expected prefix "hskey-authreq-""#,
        },
        Case {
            name: "auth reject prefixed short auth id",
            uri: "/api/v1/auth/reject",
            body: r#"{"auth_id":"hskey-authreq-short"}"#,
            expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 19",
        },
        Case {
            name: "auth approve prefixed long auth id",
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":"hskey-authreq-abcdefghijklmnopqrstuvwxy"}"#,
            expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 39",
        },
        Case {
            name: "auth reject prefixed long auth id",
            uri: "/api/v1/auth/reject",
            body: r#"{"auth_id":"hskey-authreq-abcdefghijklmnopqrstuvwxy"}"#,
            expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 39",
        },
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                case.uri,
                Some(&token),
                Body::from(case.body),
            ))
            .await
            .unwrap();
        assert_status_json_exact(resp, 400, 3, case.expected_message, case.name).await;
    }
}

#[tokio::test]
async fn grpc_gateway_node_and_debug_paths_use_upstream_shapes() {
    let (app, token, registry, _db) = fixture_with_wire_registry().await;
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
                r#"{{"user":"node-user","key":"hskey-authreq-{registration_key}","name":"debug-router","routes":["10.10.0.0/24"]}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let node_id = body["node"]["id"].as_str().unwrap().to_string();
    let _guard =
        MachineRegistry::track_stream_connection(registry, node_id.parse().expect("numeric id"));
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
            &format!("/api/v1/node/register?user=node-user&key=hskey-authreq-{registration_key}"),
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

    let policy = r#"{"tagOwners":{"tag:router":["alice@"]}}"#;
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
            &format!(
                "/api/v1/node/{node_id}/expire?expiry.seconds=1893553445&expiry.nanos=123456789"
            ),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["expiry"], "2030-01-02T03:04:05.123456789Z");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/expire?disableExpiry=true"),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert!(body["node"]["expiry"].is_null());

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!(
                "/api/v1/node/{node_id}/expire?disable_expiry=true&expiry=2030-01-02T03%3A04%3A05Z"
            ),
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("cannot set both disable_expiry and expiry")
    );

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
async fn grpc_gateway_auth_paths_use_upstream_body_shapes() {
    let (app, token) = fixture().await;
    let register_key = "g".repeat(24);
    let approve_key = "h".repeat(24);
    let reject_key = "i".repeat(24);

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"auth-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(created_user.status(), 200);

    for (key, name) in [
        (&register_key, "auth-register"),
        (&approve_key, "auth-approve"),
        (&reject_key, "auth-reject"),
    ] {
        let resp = app
            .clone()
            .oneshot(req(
                Method::POST,
                "/api/v1/debug/node",
                Some(&token),
                Body::from(format!(
                    r#"{{"user":"auth-user","key":"hskey-authreq-{key}","name":"{name}","routes":[]}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/register",
            Some(&token),
            Body::from(format!(
                r#"{{"user":"auth-user","authId":"hskey-authreq-{register_key}"}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["node"]["name"], "auth-register");
    assert_eq!(body["node"]["registerMethod"], "REGISTER_METHOD_CLI");

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/approve",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{approve_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/reject",
            Some(&token),
            Body::from(format!(r#"{{"auth_id":"hskey-authreq-{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/reject",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/approve",
            Some(&token),
            Body::from(format!(r#"{{"authId":"{approve_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_status_json(resp, 400, 3, "invalid auth_id", "auth approve bare id").await;
}

#[tokio::test]
async fn grpc_gateway_auth_terminal_reuse_preserves_first_outcome() {
    let (app, token, registration_cache, _db) = fixture_with_registration_cache().await;
    let approve_key = "j".repeat(24);
    let reject_key = "k".repeat(24);
    let binding = SshCheckBinding {
        src_node_id: 1001,
        dst_node_id: 1002,
        local_user: "root".into(),
    };

    registration_cache.insert_ssh_check(approve_key.clone(), binding.clone());
    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/approve",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{approve_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/reject",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{approve_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));
    assert_eq!(
        registration_cache.wait_for_auth(&approve_key).await,
        AuthWaitOutcome::Accepted
    );

    registration_cache.insert_ssh_check(reject_key.clone(), binding);
    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/reject",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/approve",
            Some(&token),
            Body::from(format!(r#"{{"authId":"hskey-authreq-{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));
    assert_eq!(
        registration_cache.wait_for_auth(&reject_key).await,
        AuthWaitOutcome::Rejected("auth request rejected".into())
    );
}

#[tokio::test]
async fn grpc_gateway_approve_exit_route_matches_upstream_route_shape() {
    let (app, token, registry, _db) = fixture_with_wire_registry().await;
    let registration_key = "exitrouteabcdefghijklmno";

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"exit-user"}"#),
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
                r#"{{"user":"exit-user","key":"hskey-authreq-{registration_key}","name":"exit-node","routes":["0.0.0.0/0","::/0"]}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let node_id = body["node"]["id"].as_str().unwrap().to_string();
    let _guard =
        MachineRegistry::track_stream_connection(registry, node_id.parse().expect("numeric id"));
    assert_eq!(
        body["node"]["availableRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/register?user=exit-user&key=hskey-authreq-{registration_key}"),
            Some(&token),
            Body::from(r"{}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/approve_routes"),
            Some(&token),
            Body::from(r#"{"routes":["0.0.0.0/0"]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(
        body["node"]["approvedRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
    assert_eq!(body["node"]["subnetRoutes"], serde_json::json!([]));

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/node?user=exit-user",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let node = body["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"] == node_id)
        .expect("listed exit node");
    assert_eq!(
        node["subnetRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
}

#[tokio::test]
async fn grpc_gateway_node_approve_routes_persists_go_nodes_approved_routes() {
    let (app, token, db) = fixture_with_persistent_machines().await;
    let registration_key = "persistedexitrouteabcdef";

    let created_user = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"persist-user"}"#),
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
                r#"{{"user":"persist-user","key":"hskey-authreq-{registration_key}","name":"persist-exit","routes":["0.0.0.0/0","::/0"]}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!(
                "/api/v1/node/register?user=persist-user&key=hskey-authreq-{registration_key}"
            ),
            Some(&token),
            Body::from(r"{}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let node_id = body["node"]["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/{node_id}/approve_routes"),
            Some(&token),
            Body::from(r#"{"routes":["0.0.0.0/0"]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(
        body["node"]["approvedRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );

    let raw_routes: String = sqlx::query_scalar("SELECT approved_routes FROM nodes WHERE id = ?")
        .bind(node_id.parse::<i64>().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(raw_routes, r#"["0.0.0.0/0","::/0"]"#);

    let (fresh_service, fresh_token) = service_for_db(&db, true).await;
    let fresh_app = grpc_gateway::router(fresh_service);
    let resp = fresh_app
        .oneshot(req(
            Method::GET,
            "/api/v1/node?user=persist-user",
            Some(&fresh_token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(
        body["nodes"][0]["approvedRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
    assert_eq!(
        body["nodes"][0]["subnetRoutes"],
        serde_json::json!(["0.0.0.0/0", "::/0"])
    );
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
    assert_eq!(body["preAuthKey"]["expiration"], "0001-01-01T00:00:00Z");
    assert!(
        body["preAuthKey"]["key"]
            .as_str()
            .unwrap()
            .starts_with("hskey-auth-")
    );
    let created_key = body["preAuthKey"]["key"]
        .as_str()
        .expect("created full preauth key")
        .to_string();
    assert!(!created_key.ends_with("-***"));

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
    let listed_key = body["preAuthKeys"][0]["key"]
        .as_str()
        .expect("listed preauth display key");
    assert_ne!(listed_key, created_key);
    assert!(listed_key.starts_with("hskey-auth-"));
    assert!(listed_key.ends_with("-***"));
    assert_eq!(body["preAuthKeys"][0]["expiration"], "0001-01-01T00:00:00Z");

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
    let bootstrap_key_row = keys
        .iter()
        .find(|key| key["id"] == "1")
        .expect("bootstrap key row");
    assert!(bootstrap_key_row.get("expiration").is_none());
    let new_key_row = keys
        .iter()
        .find(|key| key["id"] == "2")
        .expect("new key row");
    let new_prefix = new_key_row["prefix"].as_str().unwrap().to_string();
    assert!(new_prefix.starts_with("hskey-api-"));
    assert!(new_key_row["createdAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(new_key_row["expiration"], "0001-01-01T00:00:00Z");
    assert!(new_key_row.get("lastSeen").is_none());

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

    let candidate = r#"{"acls":[]}"#;
    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/policy/check",
            Some(&token),
            Body::from(serde_json::json!({ "policy": candidate }).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .clone()
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

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/policy/check",
            Some(&token),
            Body::from(serde_json::json!({ "policy": "{" }).to_string()),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = body_json(resp).await;
    assert_eq!(body["code"], 3);
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
