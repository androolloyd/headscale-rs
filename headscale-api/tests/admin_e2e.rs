//! End-to-end integration test for the admin GUI v0.
//!
//! Distinct from `tests/e2e.rs` (which uses the full `Server` and
//! therefore needs `--features full`); this file only exercises the
//! `admin` feature so it builds + runs under
//! `cargo test -p headscale-api --no-default-features --features admin`.
//!
//! We spin up the admin router against a fixture `WireState` machine
//! and drive ~5 representative endpoints through `tower::ServiceExt`.

#![cfg(feature = "admin")]

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use headscale_api::admin::{
    AdminState, InMemoryPreauthAdmin, PersistentUserAdmin, UserAdmin, UserRegistry,
    WireMachineAdmin, router,
};
use headscale_api::tailscale_wire::{MachineRecord, MachineRegistry};
use headscale_db::Database;
use tower::ServiceExt;

const BEARER: &str = "integration-admin-bearer-token";

fn fixture_state() -> AdminState {
    fixture_state_with_users(UserRegistry::new())
}

fn fixture_state_with_users(users: impl UserAdmin + 'static) -> AdminState {
    let reg = Arc::new(MachineRegistry::new());
    // Two fixture machines so list-vs-detail tests can't false-positive.
    reg.upsert(
        hex::encode([0xaa; 32]),
        MachineRecord::new_at(
            chrono::Utc::now(),
            hex::encode([0xaa; 32]),
            hex::encode([0xbb; 32]),
            "alice".into(),
            "alice-laptop".into(),
            std::net::Ipv4Addr::new(100, 64, 0, 5),
            false,
        ),
    );
    reg.upsert(
        hex::encode([0xcc; 32]),
        MachineRecord::new_at(
            chrono::Utc::now(),
            hex::encode([0xcc; 32]),
            hex::encode([0xdd; 32]),
            "bob".into(),
            "bob-server".into(),
            std::net::Ipv4Addr::new(100, 64, 0, 6),
            false,
        ),
    );
    AdminState::builder()
        .bearer_token(BEARER)
        .users(users)
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(2)
        .build()
}

async fn body_string(resp: axum::response::Response) -> String {
    let b = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

fn bearer(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
}

#[tokio::test]
async fn admin_router_dashboard_html_returns_200_with_bearer() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            bearer(Request::builder().method(Method::GET).uri("/admin/"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Dashboard"));
}

#[tokio::test]
async fn admin_router_machines_api_lists_two_fixture_machines() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            bearer(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/machines"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("alice-laptop"));
    assert!(body.contains("bob-server"));
}

#[tokio::test]
async fn admin_router_user_create_then_list() {
    let state = fixture_state();
    let app = router(state.clone());
    let resp = app
        .clone()
        .oneshot(
            bearer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/users")
                    .header(header::CONTENT_TYPE, "application/json"),
            )
            .body(Body::from(r#"{"name":"carol"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .oneshot(
            bearer(Request::builder().method(Method::GET).uri("/api/v1/users"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("carol"));
}

#[tokio::test]
async fn admin_router_can_use_persistent_go_user_store() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");
    let app = router(fixture_state_with_users(PersistentUserAdmin::new(
        db.pool().clone(),
    )));

    let resp = app
        .clone()
        .oneshot(
            bearer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/users")
                    .header(header::CONTENT_TYPE, "application/json"),
            )
            .body(Body::from(r#"{"name":"dave"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let stored = headscale_db::users::get_by_name(db.pool(), "dave")
        .await
        .unwrap();
    assert_eq!(stored.name, "dave");

    let app = router(fixture_state_with_users(PersistentUserAdmin::new(
        db.pool().clone(),
    )));
    let resp = app
        .oneshot(
            bearer(Request::builder().method(Method::GET).uri("/api/v1/users"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("dave"));
}

#[tokio::test]
async fn admin_router_preauth_mint_returns_full_token() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            bearer(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/preauthkeys")
                    .header(header::CONTENT_TYPE, "application/json"),
            )
            .body(Body::from(
                r#"{"user":"alice","ttl_secs":3600,"reusable":true,"ephemeral":false,"tags":["tag:dev"]}"#,
            ))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_string(resp).await;
    assert!(body.contains("hskey-auth-"));
    assert!(body.contains("tag:dev"));
    assert!(body.contains(r#""reusable":true"#));
}

#[tokio::test]
async fn admin_router_tailnet_api_reports_derp_count() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            bearer(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/tailnet"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains(r#""derp_regions":2"#));
}

#[tokio::test]
async fn admin_router_anonymous_api_rejected_with_401() {
    let app = router(fixture_state());
    let resp = app
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
    assert_eq!(
        resp.headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap(),
        r#"Bearer realm="octra-admin""#
    );
}
