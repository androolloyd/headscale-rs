//! Auth-failure / malformed-body / not-found / conflict (409 / 400 /
//! 404 / 401) coverage for the admin router. Companion to the
//! existing `src/admin/tests.rs` happy-path suite + the
//! `tests/admin_e2e.rs` integration smoke test.
//!
//! Strategy: build a fixture `AdminState` + `router`, then drive each
//! route through `tower::ServiceExt::oneshot`. No socket, no listener.

#![cfg(feature = "admin")]

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use headscale_api::admin::{
    AdminState, InMemoryPreauthAdmin, UserRegistry, WireMachineAdmin, router,
};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::{MachineRecord, MachineRegistry};
use tower::ServiceExt;

const BEARER: &str = "admin-bearer-coverage";

fn fixture_state_with_policy(policy: PolicyStore) -> AdminState {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert(
        "aa".repeat(32),
        MachineRecord {
            node_key_hex: "aa".repeat(32),
            machine_key_hex: "bb".repeat(32),
            user: "alice".into(),
            hostname: "node-1".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 5),
            disco_key: None,
            endpoints: Vec::new(),
        },
    );
    AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(1)
        .policy(policy)
        .build()
}

fn fixture_state() -> AdminState {
    fixture_state_with_policy(PolicyStore::new())
}

fn app() -> Router {
    router(fixture_state())
}

async fn body(resp: Response) -> String {
    let b = to_bytes(resp.into_body(), 8 * 1024 * 1024).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

fn req_authed(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap()
}

fn req_post_json(uri: &str, body: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

fn req_put_text(uri: &str, body: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(header::CONTENT_TYPE, "text/plain");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_owned())).unwrap()
}

// ---------------------------------------------------------------------------
// Auth gate: every API route rejects anonymous
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_users_list_anonymous_401() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(body(resp).await.contains(r#""error":"unauthorized""#));
}

#[tokio::test]
async fn api_machines_list_anonymous_401() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/machines")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_preauthkeys_list_anonymous_401() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/preauthkeys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_policy_get_anonymous_401() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_policy_put_anonymous_401() {
    let resp = app()
        .oneshot(req_put_text(
            "/api/v1/policy",
            r#"{"version":1,"rules":[]}"#,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_policy_validate_anonymous_401() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/policy/validate",
            r#"{"version":1,"rules":[]}"#,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_with_wrong_bearer_token_401() {
    let resp = app()
        .oneshot(req_authed(Method::GET, "/api/v1/users"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK); // sanity: right bearer works

    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users")
                .header(header::AUTHORIZATION, "Bearer not-the-right-one")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_with_malformed_authorization_header_401() {
    // Missing `Bearer ` prefix.
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/users")
                .header(header::AUTHORIZATION, BEARER) // no Bearer prefix
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Malformed JSON bodies — 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_users_create_with_invalid_json_returns_400() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/users",
            "this is not json",
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body(resp).await.contains(r#""error""#));
}

#[tokio::test]
async fn api_users_create_missing_required_field_returns_400() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"other":"field"}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_preauthkeys_create_with_invalid_json_returns_400() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/preauthkeys",
            "{ garbage",
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_preauthkeys_create_with_empty_user_returns_400() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/preauthkeys",
            r#"{"user":"","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        body(resp)
            .await
            .to_lowercase()
            .contains("must be non-empty")
    );
}

// ---------------------------------------------------------------------------
// Not-found / conflict semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_machine_get_unknown_id_returns_404() {
    let bad = "ff".repeat(32);
    let resp = app()
        .oneshot(req_authed(Method::GET, &format!("/api/v1/machines/{bad}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert!(body(resp).await.contains(r#""error":"not found""#));
}

#[tokio::test]
async fn api_machine_expire_unknown_id_returns_404() {
    let bad = "ff".repeat(32);
    let resp = app()
        .oneshot(req_authed(
            Method::POST,
            &format!("/api/v1/machines/{bad}/expire"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_machine_delete_unknown_id_returns_404() {
    let bad = "ff".repeat(32);
    let resp = app()
        .oneshot(req_authed(
            Method::DELETE,
            &format!("/api/v1/machines/{bad}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_user_delete_unknown_returns_404() {
    let resp = app()
        .oneshot(req_authed(Method::DELETE, "/api/v1/users/ghost"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_users_duplicate_create_returns_400() {
    // Build one router (so the in-memory user registry is shared
    // across both oneshot calls); clone the router for each call.
    let app = router(fixture_state());
    let r = app
        .clone()
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"name":"alice"}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // Duplicate ⇒ 400. (The handler maps `UserRegistryError::Exists`
    // to BAD_REQUEST, not 409 — verify the contract as-is.)
    let r = app
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"name":"alice"}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let b = body(r).await;
    assert!(b.contains("already exists"));
}

#[tokio::test]
async fn api_preauth_expire_unknown_prefix_returns_404() {
    let resp = app()
        .oneshot(req_authed(
            Method::POST,
            "/api/v1/preauthkeys/octrapreauth-never/expire",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_preauth_expire_short_prefix_returns_404() {
    // Prefix < 4 chars surfaces as `PreauthAdminError::Invalid`, which
    // the API handler maps to 404 (same path as Unknown). Verify the
    // wire contract.
    let resp = app()
        .oneshot(req_authed(Method::POST, "/api/v1/preauthkeys/x/expire"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Policy routes — get/put/validate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_policy_get_returns_loaded_false_when_unset() {
    let resp = app()
        .oneshot(req_authed(Method::GET, "/api/v1/policy"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body(resp).await;
    assert!(b.contains(r#""loaded":false"#));
    assert!(b.contains(r#""policy":null"#));
    assert!(b.contains(r#""raw":null"#));
}

#[tokio::test]
async fn api_policy_put_then_get_round_trips_raw() {
    let policy = PolicyStore::new();
    let app = router(fixture_state_with_policy(policy));
    let raw = "{\n  // hello\n  \"version\":1,\n  \"rules\":[]\n}";
    let resp = app
        .clone()
        .oneshot(req_put_text("/api/v1/policy", raw, Some(BEARER)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body(resp).await.contains(r#""applied":true"#));

    // GET — raw bytes must be byte-identical with comments.
    let resp = app
        .oneshot(req_authed(Method::GET, "/api/v1/policy"))
        .await
        .unwrap();
    let b = body(resp).await;
    assert!(b.contains(r#""loaded":true"#));
    assert!(b.contains("// hello"), "raw must preserve comments");
}

#[tokio::test]
async fn api_policy_put_invalid_hujson_returns_400_and_preserves_existing() {
    let app = router(fixture_state());
    // First: load a known-good policy.
    let good =
        r#"{"version":1,"rules":[{"action":"accept","src":["*"],"dst":["*"],"ports":["*/*"]}]}"#;
    let resp = app
        .clone()
        .oneshot(req_put_text("/api/v1/policy", good, Some(BEARER)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Then: try to overwrite with garbage; previous doc must persist.
    let resp = app
        .clone()
        .oneshot(req_put_text(
            "/api/v1/policy",
            "definitely not json",
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body(resp).await.contains(r#""error""#));

    // GET — original good doc is still there.
    let resp = app
        .oneshot(req_authed(Method::GET, "/api/v1/policy"))
        .await
        .unwrap();
    assert!(body(resp).await.contains(r#""loaded":true"#));
}

#[tokio::test]
async fn api_policy_validate_good_returns_rule_count() {
    let app = router(fixture_state());
    let raw = r#"{
        "version": 1,
        "rules": [
            {"action":"accept","src":["*"],"dst":["*"],"ports":["tcp/22"]},
            {"action":"accept","src":["group:a"],"dst":["*"],"ports":["tcp/80"]}
        ],
        "groups": {"a": ["100.64.0.1"]}
    }"#;
    let resp = app
        .oneshot(req_post_json("/api/v1/policy/validate", raw, Some(BEARER)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body(resp).await;
    assert!(b.contains(r#""valid":true"#));
    assert!(b.contains(r#""rules":2"#));
}

#[tokio::test]
async fn api_policy_validate_bad_returns_400() {
    let resp = app()
        .oneshot(req_post_json(
            "/api/v1/policy/validate",
            r#"{"version":1,"rules":[{"action":"nope","src":["*"],"dst":["*"]}]}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body(resp).await.contains(r#""error""#));
}

#[tokio::test]
async fn api_policy_put_non_utf8_returns_400() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/policy")
                .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
                .body(Body::from(vec![0xff, 0xfe, 0xfd]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(body(resp).await.to_lowercase().contains("utf-8"));
}

// ---------------------------------------------------------------------------
// HTML routes — auth redirect vs. authed render
// ---------------------------------------------------------------------------

#[tokio::test]
async fn html_machine_expire_without_csrf_when_session_authed_is_forbidden() {
    // Bearer auth bypasses CSRF (see `check_csrf` for AuthOutcome::Bearer).
    // So the test here is: a session-cookie-authed POST without a CSRF
    // token returns 403. We construct a session payload by hitting
    // /admin/login first.
    let app = router(fixture_state());

    // Login → grab session cookie.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={BEARER}")))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let session = cookie.split(';').next().unwrap().trim().to_string();

    // POST /admin/machines/<id>/expire as a session-authed client
    // *without* the csrf form field ⇒ 403.
    let id = "aa".repeat(32);
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/admin/machines/{id}/expire"))
                .header(header::COOKIE, session)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(body(resp).await.contains("bad csrf"));
}

#[tokio::test]
async fn html_user_create_anonymous_redirects_to_login() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/users")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("name=alice"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(loc, "/admin/login");
}

#[tokio::test]
async fn html_login_form_renders_without_auth() {
    let resp = app()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/admin/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let b = body(resp).await;
    assert!(b.to_lowercase().contains("token"));
}

// ---------------------------------------------------------------------------
// Round-trip CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_users_full_crud_round_trip() {
    let app = router(fixture_state());
    // Create
    let r = app
        .clone()
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"name":"carol"}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    // List sees it
    let r = app
        .clone()
        .oneshot(req_authed(Method::GET, "/api/v1/users"))
        .await
        .unwrap();
    assert!(body(r).await.contains("carol"));
    // Delete
    let r = app
        .clone()
        .oneshot(req_authed(Method::DELETE, "/api/v1/users/carol"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    // Subsequent delete ⇒ 404
    let r = app
        .oneshot(req_authed(Method::DELETE, "/api/v1/users/carol"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_preauthkey_mint_then_expire_round_trip() {
    let app = router(fixture_state());
    let r = app
        .clone()
        .oneshot(req_post_json(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let b = body(r).await;
    // Pluck out the key — minimal hand-parse (no serde dep in the
    // test) to avoid coupling to the wire DTO.
    let key_marker = r#""key":""#;
    let start = b.find(key_marker).unwrap() + key_marker.len();
    let end = b[start..].find('"').unwrap() + start;
    let key = &b[start..end];
    assert!(key.starts_with("octrapreauth-"));
    let prefix = &key[..18];

    let r = app
        .oneshot(req_authed(
            Method::POST,
            &format!("/api/v1/preauthkeys/{prefix}/expire"),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn api_tailnet_reports_policy_loaded_flag() {
    let policy = PolicyStore::new();
    let app = router(fixture_state_with_policy(policy.clone()));
    let r = app
        .clone()
        .oneshot(req_authed(Method::GET, "/api/v1/tailnet"))
        .await
        .unwrap();
    assert!(body(r).await.contains(r#""policy_loaded":false"#));

    // Push a policy via PUT, then re-check.
    let r = app
        .clone()
        .oneshot(req_put_text(
            "/api/v1/policy",
            r#"{"version":1,"rules":[]}"#,
            Some(BEARER),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = app
        .oneshot(req_authed(Method::GET, "/api/v1/tailnet"))
        .await
        .unwrap();
    assert!(body(r).await.contains(r#""policy_loaded":true"#));
}
