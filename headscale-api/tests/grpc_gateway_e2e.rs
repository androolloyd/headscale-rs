//! grpc-gateway-compatible `/api/v1` route coverage.

#![cfg(all(feature = "admin", feature = "full"))]

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, header},
    response::Response,
};
use headscale_api::admin::{
    ApiKeyAdmin, ApiKeyMintRequest, PersistentApiKeyAdmin, PersistentMachineAdmin,
    PersistentPreauthAdmin, PersistentUserAdmin, WireMachineAdmin,
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
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
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

async fn body_json(resp: Response) -> Value {
    let body = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "response body was not JSON: {e}\n{}",
            String::from_utf8_lossy(&body)
        )
    })
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

async fn assert_plain_unauthorized(resp: Response) {
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
async fn grpc_gateway_health_missing_auth_returns_plain_unauthorized() {
    let (app, token) = fixture().await;

    let resp = app
        .clone()
        .oneshot(req(Method::GET, "/api/v1/health", None, Body::empty()))
        .await
        .unwrap();
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

    let resp = app
        .oneshot(req(
            Method::GET,
            "/api/v1/user/1",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_status_json_exact(resp, 501, 12, "Method Not Allowed", "method mismatch").await;
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
    assert_status_json_exact(
        resp,
        500,
        2,
        "database ping failed: forced offline",
        "health database failure",
    )
    .await;
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
async fn grpc_gateway_body_unknown_and_duplicate_fields_are_status_json() {
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
            name: "create user unknown field",
            method: Method::POST,
            uri: "/api/v1/user",
            body: r#"{"name":"alice","unknown":1}"#,
            message_fragment: r#"unknown field "unknown""#,
        },
        Case {
            name: "auth approve unknown field",
            method: Method::POST,
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":"abc","unknown":1}"#,
            message_fragment: r#"unknown field "unknown""#,
        },
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
            name: "expire api key null prefix body field",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: r#"{"prefix":null}"#,
            expected_message: "invalid value for string field prefix: null",
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
    }

    let (app, token) = fixture().await;

    for case in [
        Case {
            name: "null uint64 body field",
            method: Method::POST,
            uri: "/api/v1/preauthkey/expire",
            body: r#"{"id":null}"#,
            message_fragment: "invalid value for uint64 field id: null",
        },
        Case {
            name: "base-prefixed body uint64",
            method: Method::POST,
            uri: "/api/v1/preauthkey/expire",
            body: r#"{"id":"0x1"}"#,
            message_fragment: r#"invalid value for uint64 field id: "0x1""#,
        },
        Case {
            name: "null string body field",
            method: Method::POST,
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":null}"#,
            message_fragment: "invalid value for string field authId: null",
        },
        Case {
            name: "object timestamp body field",
            method: Method::POST,
            uri: "/api/v1/apikey",
            body: r#"{"expiration":{"seconds":4102444800}}"#,
            message_fragment: "unexpected token { for timestamp field expiration",
        },
        Case {
            name: "timestamp body underflow",
            method: Method::POST,
            uri: "/api/v1/apikey",
            body: r#"{"expiration":"0001-01-01T00:00:00+01:00"}"#,
            message_fragment: r#"google.protobuf.Timestamp value out of range: "0001-01-01T00:00:00+01:00""#,
        },
        Case {
            name: "string bool body field",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"reusable":"true"}"#,
            message_fragment: r#"invalid value for bool field reusable: "true""#,
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

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            "/api/v1/user",
            Some(&token),
            Body::from(r#"{"name":"hex-path-user"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["user"]["id"], "1");

    let resp = app
        .oneshot(req(
            Method::DELETE,
            "/api/v1/user/0x1",
            Some(&token),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));
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
            expected_http_status: 409,
            expected_grpc_code: 6,
            expected_message: "status-dupe",
        },
        Case {
            name: "delete missing user",
            method: Method::DELETE,
            uri: "/api/v1/user/404",
            body: "",
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "404",
        },
        Case {
            name: "create preauth key missing user",
            method: Method::POST,
            uri: "/api/v1/preauthkey",
            body: r#"{"user":"404"}"#,
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "user not found",
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
            name: "expire api key missing selector",
            method: Method::POST,
            uri: "/api/v1/apikey/expire",
            body: "{}",
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "either prefix or id must be provided",
        },
        Case {
            name: "delete api key conflicting selectors",
            method: Method::DELETE,
            uri: "/api/v1/apikey/prefix?id=1",
            body: "",
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: "only one of prefix or id can be provided",
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
            name: "auth approve no pending session",
            method: Method::POST,
            uri: "/api/v1/auth/approve",
            body: r#"{"authId":"aaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            expected_http_status: 404,
            expected_grpc_code: 5,
            expected_message: "no pending auth session for auth_id aaaaaaaaaaaaaaaaaaaaaaaa",
        },
        Case {
            name: "auth reject invalid prefixed auth id",
            method: Method::POST,
            uri: "/api/v1/auth/reject",
            body: r#"{"authId":"hskey-authreq-short"}"#,
            expected_http_status: 400,
            expected_grpc_code: 3,
            expected_message: r#"invalid auth_id: expected 24 characters after "hskey-authreq-", got 5"#,
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
                r#"{{"user":"node-user","key":"{registration_key}","name":"debug-router","routes":["10.10.0.0/24"]}}"#
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
                    r#"{{"user":"auth-user","key":"{key}","name":"{name}","routes":[]}}"#
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
            Body::from(format!(r#"{{"auth_id":"{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(body_json(resp).await, serde_json::json!({}));

    let resp = app
        .oneshot(req(
            Method::POST,
            "/api/v1/auth/reject",
            Some(&token),
            Body::from(format!(r#"{{"authId":"{reject_key}"}}"#)),
        ))
        .await
        .unwrap();
    assert_status_json(resp, 404, 5, "no pending auth session", "auth reject").await;
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
                r#"{{"user":"exit-user","key":"{registration_key}","name":"exit-node","routes":["0.0.0.0/0","::/0"]}}"#
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
            &format!("/api/v1/node/register?user=exit-user&key={registration_key}"),
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
                r#"{{"user":"persist-user","key":"{registration_key}","name":"persist-exit","routes":["0.0.0.0/0","::/0"]}}"#
            )),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .clone()
        .oneshot(req(
            Method::POST,
            &format!("/api/v1/node/register?user=persist-user&key={registration_key}"),
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
    assert_status_json_exact(
        resp,
        500,
        2,
        "loading ACL from database: acl policy not found",
        "policy missing database row",
    )
    .await;
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
