//! End-to-end tests for the persistent preauth-key admin surface.
//!
//! Wires [`PersistentPreauthAdmin`] into the admin router and drives
//! it through `tower::ServiceExt::oneshot` (no socket binding) to
//! exercise:
//!
//! * `POST /api/v1/preauthkeys` ⇒ creates a row + returns the
//!   plaintext token (mirror of the Go upstream's
//!   `hscontrol/grpcv1.go::CreatePreAuthKey` body shape).
//! * `GET /api/v1/preauthkeys` ⇒ lists all rows (newest first).
//! * `POST /api/v1/preauthkeys/<prefix>/expire` ⇒ marks the row as
//!   expired (parity with Go `ExpirePreAuthKey`).
//! * `PersistentPreauthAdmin::try_use` ⇒ atomic single-use redemption
//!   that surfaces the `used_at` stamp the next `list` reports.
//!
//! These tests intentionally bypass the wire layer's
//! `/machine/register` flow: that surface is frozen by the wire
//! freeze (see brief), and the brief's "list-with-used-at" step is
//! the admin-side equivalent of "the wire layer redeemed this key".

#![cfg(feature = "admin")]

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use headscale_api::admin::{
    AdminState, PersistentPreauthAdmin, PersistentUserAdmin, UserAdmin, UserRegistry,
    WireMachineAdmin, router,
};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::MachineRegistry;
use headscale_db::Database;
use tower::ServiceExt;

const BEARER: &str = "preauth-e2e-bearer";

async fn fixture() -> (Router, PersistentPreauthAdmin) {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    users.create("alice").await.expect("seed alice user");
    users.create("bob").await.expect("seed bob user");
    users.create("carol").await.expect("seed carol user");
    let store =
        PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone());
    let reg = Arc::new(MachineRegistry::new());
    let state = AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(reg)))
        .preauth(Arc::new(store.clone()))
        .derp_regions(0)
        .policy(PolicyStore::new())
        .build();
    (router(state), store)
}

async fn body_text(resp: Response) -> String {
    let b = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    String::from_utf8(b.to_vec()).unwrap()
}

async fn body_json(resp: Response) -> serde_json::Value {
    let text = body_text(resp).await;
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("not json: {e}\n{text}"))
}

fn req_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn req_get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap()
}

fn req_post_empty(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap()
}

// =========================================================================
// E2E flows
// =========================================================================

#[tokio::test]
async fn post_create_then_get_list_round_trip() {
    let (app, _store) = fixture().await;
    let resp = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":["tag:dev"]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    let key = created["key"].as_str().expect("key in response");
    assert!(key.starts_with("hskey-auth-"));
    assert_eq!(created["user"], "alice");
    assert_eq!(created["reusable"], false);
    assert_eq!(created["tags"][0], "tag:dev");

    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    let arr = list.as_array().expect("list is array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["key"], key);
}

#[tokio::test]
async fn post_create_with_reusable_true_persists_flag() {
    let (app, _store) = fixture().await;
    let resp = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":true,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list[0]["reusable"], true);
}

#[tokio::test]
async fn post_create_with_ephemeral_true_persists_flag() {
    let (app, _store) = fixture().await;
    let _ = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":true,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list[0]["ephemeral"], true);
}

#[tokio::test]
async fn post_create_with_tags_round_trips() {
    let (app, _store) = fixture().await;
    let _ = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":["tag:a","tag:b","tag:c"]}"#,
        ))
        .await
        .unwrap();
    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    let list = body_json(resp).await;
    let tags = list[0]["tags"].as_array().expect("tags array");
    assert_eq!(tags.len(), 3);
}

#[tokio::test]
async fn try_use_via_store_after_admin_mint() {
    let (app, store) = fixture().await;
    let resp = app
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let key = created["key"].as_str().unwrap().to_string();
    // Direct call into the store — mirrors what the wire layer's
    // `PreauthRedeemer` adapter does at register-time.
    let row = store.try_use(&key).await.expect("redeem");
    assert_eq!(row.user_id, "1");
    assert!(row.used_at.is_some(), "single-use must stamp used_at");
}

#[tokio::test]
async fn list_after_redemption_shows_redemptions_eq_one() {
    let (app, store) = fixture().await;
    let resp = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    let _ = store.try_use(&key).await.unwrap();

    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    let list = body_json(resp).await;
    assert_eq!(list[0]["redemptions"], 1);
}

#[tokio::test]
async fn second_redemption_of_single_use_key_is_rejected() {
    let (app, store) = fixture().await;
    let resp = app
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    let _first = store.try_use(&key).await.unwrap();
    let second = store.try_use(&key).await.unwrap_err();
    assert_eq!(second, headscale_db::preauth_keys::UseError::AlreadyUsed);
}

#[tokio::test]
async fn reusable_key_redeems_n_times_via_store() {
    let (app, store) = fixture().await;
    let resp = app
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":true,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    for _ in 0..4 {
        store
            .try_use(&key)
            .await
            .expect("reusable can redeem again");
    }
}

#[tokio::test]
async fn expire_endpoint_marks_row_expired() {
    let (app, store) = fixture().await;
    let resp = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    // The admin route takes a prefix in the URL path — match what the
    // CLI sends a display prefix (`hskey-auth-<12>-***`); a shorter
    // unique token prefix is accepted by the admin route.
    let head_len = "hskey-auth-".len() + 12;
    let prefix = &key[..head_len];

    let resp = app
        .oneshot(req_post_empty(&format!(
            "/api/v1/preauthkeys/{prefix}/expire"
        )))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Subsequent `try_use` must surface the expiry.
    let e = store.try_use(&key).await.unwrap_err();
    assert_eq!(e, headscale_db::preauth_keys::UseError::Expired);
}

#[tokio::test]
async fn expire_unknown_prefix_returns_404() {
    let (app, _store) = fixture().await;
    let resp = app
        .oneshot(req_post_empty(
            "/api/v1/preauthkeys/hskey-auth-deadbeef/expire",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_returns_newest_first() {
    let (app, _store) = fixture().await;
    for u in ["alice", "bob", "carol"] {
        let body = format!(
            r#"{{"user":"{u}","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}}"#
        );
        let _ = app
            .clone()
            .oneshot(req_post("/api/v1/preauthkeys", &body))
            .await
            .unwrap();
        // Force a fresh second tick so created_at can differ. Even
        // without that, the ORDER BY tie-breaks on id DESC, so the
        // newest insert lands first.
    }
    let resp = app.oneshot(req_get("/api/v1/preauthkeys")).await.unwrap();
    let list = body_json(resp).await;
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["user"], "carol");
    assert_eq!(arr[2]["user"], "alice");
}

#[tokio::test]
async fn auth_gate_rejects_unauthenticated_create() {
    let (app, _store) = fixture().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/preauthkeys")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"user":"alice","ttl_secs":3600,"reusable":false,"ephemeral":false,"tags":[]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ttl_zero_creates_no_expiry_key() {
    let (app, store) = fixture().await;
    let resp = app
        .clone()
        .oneshot(req_post(
            "/api/v1/preauthkeys",
            r#"{"user":"alice","ttl_secs":0,"reusable":false,"ephemeral":false,"tags":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let key = body_json(resp).await["key"].as_str().unwrap().to_string();
    // try_use should succeed — no expiry to trip on.
    let _ = store.try_use(&key).await.unwrap();
}
