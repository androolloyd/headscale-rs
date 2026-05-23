//! Unit + integration tests for the admin router.
//!
//! Strategy: build the router with an in-memory state, then drive it
//! through `tower::ServiceExt::oneshot` — no socket, no listener. Each
//! test verifies the HTML body shape and the auth gate behaviour
//! independently.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use tower::ServiceExt;

use super::*;
use crate::tailscale_wire::{MachineRecord, MachineRegistry};

fn admin_token() -> String {
    "test-bearer-token-1234".into()
}

fn build_state() -> AdminState {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert(
        "aa".repeat(32),
        MachineRecord::new_at(
            chrono::Utc::now(),
            "aa".repeat(32),
            "bb".repeat(32),
            "alice".into(),
            "node-1".into(),
            std::net::Ipv4Addr::new(100, 64, 0, 5),
            false,
        ),
    );
    AdminState::builder()
        .bearer_token(admin_token())
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(1)
        .build()
}

fn app() -> (Router, AdminState) {
    let s = build_state();
    let r = router(s.clone());
    (r, s)
}

async fn body_str(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 64 * 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn req_get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn req_get_authed(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn req_post_form(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn req_post_json(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn anonymous_dashboard_redirects_to_login() {
    let (app, _) = app();
    let resp = app.oneshot(req_get("/admin/")).await.unwrap();
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
async fn anonymous_api_returns_401_json() {
    let (app, _) = app();
    let resp = app.oneshot(req_get("/api/v1/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_str(resp).await;
    assert!(body.contains(r#""error":"unauthorized""#));
}

#[tokio::test]
async fn bearer_token_unlocks_dashboard() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("Dashboard"));
    assert!(body.contains("Machines online"));
    assert!(body.contains("OctraVPN"));
    // basic HTML5 hygiene checks
    assert!(body.starts_with("<!DOCTYPE"));
    assert!(body.contains("</html>"));
    assert!(!body.contains("<center>"));
}

#[tokio::test]
async fn machines_page_lists_fixture_node() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/machines", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("node-1"));
    assert!(body.contains("alice"));
    assert!(body.contains("100.64.0.5"));
}

#[tokio::test]
async fn machine_detail_renders_keys() {
    let (app, _) = app();
    let id = "aa".repeat(32);
    let resp = app
        .oneshot(req_get_authed(
            &format!("/admin/machines/{id}"),
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains(&id));
    assert!(body.contains("Node key"));
    assert!(body.contains("Machine key"));
}

#[tokio::test]
async fn missing_machine_detail_returns_404() {
    let (app, _) = app();
    let bad = "ff".repeat(32);
    let resp = app
        .oneshot(req_get_authed(
            &format!("/admin/machines/{bad}"),
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn users_page_create_form_present() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/users", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("Create user"));
    assert!(body.contains("form method=\"post\" action=\"/admin/users\""));
}

#[tokio::test]
async fn api_v1_users_round_trip() {
    let (app, _) = app();
    // 1. Create
    let resp = app
        .clone()
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"name":"alice"}"#,
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_str(resp).await;
    assert!(body.contains(r#""name":"alice""#));

    // 2. List
    let resp = app
        .oneshot(req_get_authed("/api/v1/users", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("alice"));
}

#[tokio::test]
async fn api_v1_invalid_user_returns_400() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_post_json(
            "/api/v1/users",
            r#"{"name":"Bad Name!"}"#,
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_v1_preauthkey_mint_returns_full_key() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_post_json(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_str(resp).await;
    assert!(body.contains(r#""user":"alice""#));
    assert!(body.contains(r#""key":"hskey-auth-"#));
}

#[tokio::test]
async fn api_v1_machines_list_shapes_correctly() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/api/v1/machines", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    // The fixture machine should be present, with the standard fields.
    assert!(body.contains(r#""user":"alice""#));
    assert!(body.contains(r#""ipv4":"100.64.0.5""#));
    assert!(body.contains(r#""online":false"#));
}

#[tokio::test]
async fn api_v1_machines_expire_then_list_shows_offline() {
    let (app, _) = app();
    let id = "aa".repeat(32);
    let resp = app
        .clone()
        .oneshot(req_post_form(
            &format!("/api/v1/machines/{id}/expire"),
            "",
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .oneshot(req_get_authed(
            &format!("/api/v1/machines/{id}"),
            &admin_token(),
        ))
        .await
        .unwrap();
    let body = body_str(resp).await;
    assert!(body.contains(r#""online":false"#));
    assert!(body.contains(r#""expired":true"#));
}

#[tokio::test]
async fn api_v1_tailnet_returns_derp_region_count() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/api/v1/tailnet", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains(r#""derp_regions":1"#));
}

#[tokio::test]
async fn login_sets_session_cookie() {
    let (app, _) = app();
    let body = format!("token={}", urlencoding_min(&admin_token()));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with(super::SESSION_COOKIE));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn bad_login_redirects_with_error() {
    let (app, _) = app();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("token=wrong"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(loc.starts_with("/admin/login?err="));
}

#[tokio::test]
async fn expired_session_redirects_to_login() {
    // Mint an already-expired cookie with a known secret, then verify
    // the dashboard redirects.
    let state = AdminState {
        auth: AdminAuth::new_with_secret(admin_token(), [42u8; 32]),
        users: Arc::new(UserRegistry::new()),
        machines: Arc::new(NoopMachines),
        preauth: Arc::new(InMemoryPreauthAdmin::new()),
        api_keys: Arc::new(NoopApiKeyAdmin),
        derp_regions: 0,
        policy: crate::policy::PolicyStore::new(),
    };
    let app = router(state.clone());
    let payload = state.auth.mint_session(1); // expired
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/admin/")
                .header(
                    header::COOKIE,
                    format!("{}={payload}", super::SESSION_COOKIE),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_clears_cookie() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/logout", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.contains("Max-Age=0"));
}

#[tokio::test]
async fn preauthkeys_page_renders_create_form() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/preauthkeys", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("Mint key"));
    assert!(body.contains("Reusable"));
    assert!(body.contains("Ephemeral"));
}

#[tokio::test]
async fn tailnet_page_shows_derp_count() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/tailnet", &admin_token()))
        .await
        .unwrap();
    let body = body_str(resp).await;
    assert!(body.contains("Tailnet"));
    assert!(body.contains("DERP"));
}

#[tokio::test]
async fn policy_page_renders_readonly() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/policy", &admin_token()))
        .await
        .unwrap();
    let body = body_str(resp).await;
    assert!(body.contains("Access policy"));
    assert!(body.to_lowercase().contains("read-only"));
}

#[tokio::test]
async fn sessions_page_is_placeholder() {
    let (app, _) = app();
    let resp = app
        .oneshot(req_get_authed("/admin/sessions", &admin_token()))
        .await
        .unwrap();
    let body = body_str(resp).await;
    assert!(body.contains("Sessions"));
    assert!(body.contains("No sessions"));
}

#[tokio::test]
async fn xss_escaped_in_machine_detail() {
    // Inject a hostname that includes an HTML break-out attempt and
    // verify it's escaped in the rendered page.
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert(
        "aa".repeat(32),
        MachineRecord::new_at(
            chrono::Utc::now(),
            "aa".repeat(32),
            "bb".repeat(32),
            "alice".into(),
            "<script>alert(1)</script>".into(),
            std::net::Ipv4Addr::new(100, 64, 0, 6),
            false,
        ),
    );
    let state = AdminState::builder()
        .bearer_token(admin_token())
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .build();
    let app = router(state);
    let resp = app
        .oneshot(req_get_authed(
            &format!("/admin/machines/{}", "aa".repeat(32)),
            &admin_token(),
        ))
        .await
        .unwrap();
    let body = body_str(resp).await;
    // The literal <script> must NOT appear unescaped in the rendered body.
    assert!(!body.contains("<script>alert(1)</script>"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
}

// -- Policy CRUD --------------------------------------------------------
//
// The wire layer's `/map` consumer is covered by an end-to-end test
// in `octravpn-node/tests/policy_e2e.rs`. Here we pin the admin-side
// HTTP contract: PUT applies a parsed doc, GET round-trips raw bytes,
// validate-only doesn't mutate, and bearer-auth gates everything.

fn req_put_text(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn req_post_text(uri: &str, body: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn policy_put_then_get_round_trip() {
    let (app, _) = app();
    let raw = r#"{ "acls":[
        {"action":"accept","proto":"tcp","src":["*"],"dst":["*:22"]}
    ]}"#;
    let resp = app
        .clone()
        .oneshot(req_put_text("/api/v1/policy", raw, &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["applied"], serde_json::Value::Bool(true));
    assert_eq!(v["rules"], serde_json::json!(1));

    let resp = app
        .oneshot(req_get_authed("/api/v1/policy", &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["loaded"], serde_json::Value::Bool(true));
    assert_eq!(v["policy"]["rules"][0]["action"], "accept");
    // Raw bytes round-trip verbatim.
    assert!(v["raw"].as_str().unwrap().contains(r#""proto":"tcp""#));
    assert!(v["raw"].as_str().unwrap().contains("*:22"));
}

#[tokio::test]
async fn policy_put_rejects_invalid_doc() {
    let (app, _) = app();
    let bad = r#"{"acls":[{"action":"bogus","src":["*"],"dst":["*:*"]}]}"#;
    let resp = app
        .oneshot(req_put_text("/api/v1/policy", bad, &admin_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_str(resp).await;
    assert!(
        body.contains("error"),
        "PUT rejection must carry a structured error: {body}"
    );
}

#[tokio::test]
async fn policy_validate_does_not_mutate() {
    let (app, state) = app();
    assert!(!state.policy.is_loaded(), "store starts empty");
    let good = r#"{"acls":[]}"#;
    let resp = app
        .clone()
        .oneshot(req_post_text(
            "/api/v1/policy/validate",
            good,
            &admin_token(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_str(resp).await;
    assert!(body.contains("\"valid\":true"));
    assert!(
        !state.policy.is_loaded(),
        "validate must not mutate the store"
    );
}

#[tokio::test]
async fn policy_endpoints_require_bearer() {
    let (app, _) = app();
    // No bearer header at all.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/api/v1/policy")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"acls":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/policy/validate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"acls":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Tiny urlencode for the login form. Keeps the test deps zero — we
/// only need to escape `=` and `+` for the bearer token, but the
/// fixture token is alpha-num plus `-`, so this is identity-mapping.
fn urlencoding_min(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}
