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
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
};
use headscale_api::admin::{
    router, AdminState, InMemoryPreauthAdmin, UserRegistry, WireMachineAdmin,
};
use headscale_api::tailscale_wire::{MachineRecord, MachineRegistry};
use tower::ServiceExt;

const BEARER: &str = "integration-admin-bearer-token";

fn fixture_state() -> AdminState {
    let reg = Arc::new(MachineRegistry::new());
    // Two fixture machines so list-vs-detail tests can't false-positive.
    reg.upsert(
        hex::encode([0xaa; 32]),
        MachineRecord {
            node_key_hex: hex::encode([0xaa; 32]),
            machine_key_hex: hex::encode([0xbb; 32]),
            user: "alice".into(),
            hostname: "alice-laptop".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 5),
        },
    );
    reg.upsert(
        hex::encode([0xcc; 32]),
        MachineRecord {
            node_key_hex: hex::encode([0xcc; 32]),
            machine_key_hex: hex::encode([0xdd; 32]),
            user: "bob".into(),
            hostname: "bob-server".into(),
            ipv4: std::net::Ipv4Addr::new(100, 64, 0, 6),
        },
    );
    AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
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
            bearer(Request::builder().method(Method::GET).uri("/api/v1/machines"))
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
    assert!(body.contains("octrapreauth-"));
    assert!(body.contains("tag:dev"));
    assert!(body.contains(r#""reusable":true"#));
}

#[tokio::test]
async fn admin_router_tailnet_api_reports_derp_count() {
    let app = router(fixture_state());
    let resp = app
        .oneshot(
            bearer(Request::builder().method(Method::GET).uri("/api/v1/tailnet"))
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
