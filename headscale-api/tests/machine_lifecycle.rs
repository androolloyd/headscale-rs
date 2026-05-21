//! P1 lifecycle integration tests: admin verbs (`expire`, `logout`,
//! `rename`, `delete`, `tags`) ↔ wire `/map` long-poll behaviour.
//!
//! Each test stands up a complete `WireState` (with a `MachineRegistry`
//! shared by both the wire router and the admin `WireMachineAdmin`),
//! drives an admin verb through the JSON API surface, and then checks
//! the wire `/map` handler emits the expected follow-up. Mirrors the
//! upstream `juanfont/headscale@main:hscontrol/db/node_test.go`
//! scenarios:
//!
//! | upstream Go test                              | Rust counterpart                                  |
//! |-----------------------------------------------|---------------------------------------------------|
//! | `TestSetExpiry`                               | `admin_expire_then_map_returns_logout`            |
//! | `TestNodeLogout`                              | `admin_logout_clears_keys_and_expires_now`        |
//! | `TestNodeRename`                              | `admin_rename_round_trip`                         |
//! | `TestDeleteNode`                              | `admin_delete_removes_from_list_and_wire`         |
//! | `TestSetTags`                                 | `admin_set_tags_round_trip`                       |
//! | `TestEphemeralGarbageCollect`                 | `gc_ephemeral_removes_stale_devices`              |
//! | `TestListEphemeralNodes`                      | `gc_ephemeral_leaves_fresh_devices`               |
//!
//! Tests run under `--features admin` only — the wire-only crate can
//! build without admin, but the integration scenarios exercise both
//! sides of the contract.

#![cfg(feature = "admin")]

use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use headscale_api::admin::{
    AdminState, InMemoryPreauthAdmin, UserRegistry, WireMachineAdmin, router as admin_router,
};
use headscale_api::tailscale_wire::{
    MachineRecord, MachineRegistry, WireState, router as wire_router,
};
use tower::ServiceExt;

const BEARER: &str = "lifecycle-it-bearer-token";

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn mk_record(id_byte: u8, host: &str, last_octet: u8, ephemeral: bool) -> MachineRecord {
    MachineRecord::new_at(
        now(),
        hex::encode([id_byte; 32]),
        hex::encode([id_byte.wrapping_add(0x10); 32]),
        "alice".into(),
        host.into(),
        std::net::Ipv4Addr::new(100, 64, 0, last_octet),
        ephemeral,
    )
}

/// Build a `WireState` + a co-tenant `AdminState` that share the same
/// `MachineRegistry`. The lifecycle integration tests need this so an
/// admin mutation lands on the same registry the wire `/map` handler
/// reads.
fn fixture(registry: Arc<MachineRegistry>) -> (WireState, AdminState) {
    let dir = tempfile::tempdir().unwrap();
    let server = Arc::new(
        headscale_api::tailscale_wire::noise::ServerNoiseKey::load_or_generate(dir.path()).unwrap(),
    );

    // Local always-fail preauth — none of the lifecycle tests register
    // via the wire layer; they insert records directly into the
    // registry to keep the test surface tight.
    struct DenyAll;
    #[async_trait::async_trait]
    impl headscale_api::tailscale_wire::PreauthRedeemer for DenyAll {
        async fn redeem(
            &self,
            _key: &str,
        ) -> Result<
            headscale_api::tailscale_wire::RedeemOk,
            headscale_api::tailscale_wire::RedeemError,
        > {
            Err(headscale_api::tailscale_wire::RedeemError::Unknown)
        }
    }
    struct ZeroIp;
    impl headscale_api::tailscale_wire::IpAllocator for ZeroIp {
        fn allocate(
            &self,
            _: &str,
        ) -> Result<std::net::Ipv4Addr, headscale_api::tailscale_wire::AllocError> {
            Ok(std::net::Ipv4Addr::new(100, 64, 0, 1))
        }
    }

    let wire = WireState {
        server_noise_key: server,
        preauth: Arc::new(DenyAll),
        ip_allocator: Arc::new(ZeroIp),
        machines: registry.clone(),
        derp_map: Arc::new(headscale_api::tailscale_wire::DerpMap::default()),
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock: headscale_api::tailscale_wire::KnockConfig::disabled(),
        dns: Arc::new(headscale_api::dns::DnsStore::new()),
        public_control_url: None,
    };
    // tempdir held only inside this fn; the wire layer never reads
    // from it after construction, so leaking is fine for the test.
    std::mem::forget(dir);

    let admin = AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(registry)))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(0)
        .build();
    (wire, admin)
}

/// Send a `POST /api/v1/machines/{id}/<verb>` with the supplied JSON
/// body. Returns the response status + decoded body. Bearer auth is
/// always present.
async fn admin_post(
    admin: &AdminState,
    id: &str,
    verb: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let router = admin_router(admin.clone());
    let path = format!("/api/v1/machines/{id}/{verb}");
    let req = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap_or_default();
    (status, body)
}

/// `DELETE /api/v1/machines/{id}` shorthand.
async fn admin_delete(admin: &AdminState, id: &str) -> StatusCode {
    let router = admin_router(admin.clone());
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/v1/machines/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    resp.status()
}

/// `POST /machine/nodekey:{hex}/map` returning the decoded JSON
/// response. The wire handler returns `MapResponse` JSON for
/// `Stream: false` requests (the default body in this helper).
async fn wire_map(wire: &WireState, node_key_hex: &str) -> (StatusCode, serde_json::Value) {
    let router = wire_router(wire.clone());
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/machine/nodekey:{node_key_hex}/map"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"OmitPeers":true}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// `GET /api/v1/machines/{id}` returning the decoded JSON.
async fn admin_get(admin: &AdminState, id: &str) -> (StatusCode, serde_json::Value) {
    let router = admin_router(admin.clone());
    let req = Request::builder()
        .uri(format!("/api/v1/machines/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test]
async fn admin_expire_then_map_returns_logout() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("aa".repeat(32), mk_record(0xaa, "node-1", 10, false));
    let (wire, admin) = fixture(reg.clone());

    // Pre-expire /map happy path — no NodeKeyExpired bit.
    let (s, v) = wire_map(&wire, &"aa".repeat(32)).await;
    assert_eq!(s, StatusCode::OK);
    assert_ne!(v["NodeKeyExpired"], serde_json::Value::Bool(true));

    // Admin POST /expire (no body → expire immediately).
    let (s, _) = admin_post(&admin, &"aa".repeat(32), "expire", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Next /map carries `NodeKeyExpired: true`.
    let (s, v) = wire_map(&wire, &"aa".repeat(32)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["NodeKeyExpired"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn admin_expire_with_iso_timestamp() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("aa".repeat(32), mk_record(0xaa, "node-1", 10, false));
    let (_wire, admin) = fixture(reg.clone());

    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let (s, _) = admin_post(
        &admin,
        &"aa".repeat(32),
        "expire",
        serde_json::json!({ "expiry": past }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rec = reg.get(&"aa".repeat(32)).unwrap();
    assert!(rec.is_expired_at(chrono::Utc::now()));
}

#[tokio::test]
async fn admin_expire_invalid_timestamp_400() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("aa".repeat(32), mk_record(0xaa, "node-1", 10, false));
    let (_wire, admin) = fixture(reg);
    let (s, body) = admin_post(
        &admin,
        &"aa".repeat(32),
        "expire",
        serde_json::json!({ "expiry": "not-a-timestamp" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid expiry"));
}

#[tokio::test]
async fn admin_logout_clears_keys_and_expires_now() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("bb".repeat(32), mk_record(0xbb, "node-2", 11, false));
    let (wire, admin) = fixture(reg.clone());

    let (s, _) = admin_post(&admin, &"bb".repeat(32), "logout", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let rec = reg.get(&"bb".repeat(32)).expect("record still present");
    assert!(rec.machine_key_hex.is_empty());
    assert!(rec.expiry.is_some());

    // /map sees the logout bit.
    let (_, v) = wire_map(&wire, &"bb".repeat(32)).await;
    assert_eq!(v["NodeKeyExpired"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn admin_rename_round_trip() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("cc".repeat(32), mk_record(0xcc, "old-host", 12, false));
    let (_wire, admin) = fixture(reg.clone());

    let (s, _) = admin_post(
        &admin,
        &"cc".repeat(32),
        "rename",
        serde_json::json!({ "hostname": "new-host" }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(reg.get(&"cc".repeat(32)).unwrap().hostname, "new-host");

    // Admin DTO reflects the new name.
    let (s, v) = admin_get(&admin, &"cc".repeat(32)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "new-host");
}

#[tokio::test]
async fn admin_rename_empty_hostname_400() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("dd".repeat(32), mk_record(0xdd, "old-host", 13, false));
    let (_wire, admin) = fixture(reg);

    let (s, body) = admin_post(
        &admin,
        &"dd".repeat(32),
        "rename",
        serde_json::json!({ "hostname": "" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("hostname"));
}

#[tokio::test]
async fn admin_delete_removes_from_list_and_wire() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("ee".repeat(32), mk_record(0xee, "node-3", 14, false));
    reg.upsert("ff".repeat(32), mk_record(0xff, "node-4", 15, false));
    let (wire, admin) = fixture(reg.clone());

    let s = admin_delete(&admin, &"ee".repeat(32)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Wire registry no longer has the row.
    assert!(reg.get(&"ee".repeat(32)).is_none());
    assert_eq!(reg.len(), 1);

    // Admin list excludes it.
    let router = admin_router(admin.clone());
    let req = Request::builder()
        .uri("/api/v1/machines")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let absent_id = "ee".repeat(32);
    let any_ee = list
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["id"].as_str() == Some(absent_id.as_str()));
    assert!(!any_ee, "deleted node must not show in /api/v1/machines");

    // /map for the deleted node returns 404.
    let (s, _) = wire_map(&wire, &"ee".repeat(32)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_set_tags_round_trip() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("11".repeat(32), mk_record(0x11, "node-tags", 16, false));
    let (_wire, admin) = fixture(reg.clone());

    let (s, _) = admin_post(
        &admin,
        &"11".repeat(32),
        "tags",
        serde_json::json!({ "tags": ["tag:prod", "tag:web"] }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let rec = reg.get(&"11".repeat(32)).unwrap();
    assert_eq!(rec.forced_tags, vec!["tag:prod", "tag:web"]);

    // Admin DTO surfaces the tags.
    let (_, v) = admin_get(&admin, &"11".repeat(32)).await;
    assert_eq!(v["tags"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn admin_set_tags_empty_clears() {
    let reg = Arc::new(MachineRegistry::new());
    let mut r = mk_record(0x22, "node-clear", 17, false);
    r.forced_tags = vec!["tag:old".into()];
    reg.upsert("22".repeat(32), r);
    let (_wire, admin) = fixture(reg.clone());

    let (s, _) = admin_post(
        &admin,
        &"22".repeat(32),
        "tags",
        serde_json::json!({ "tags": [] }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(reg.get(&"22".repeat(32)).unwrap().forced_tags.is_empty());
}

#[tokio::test]
async fn admin_verbs_on_unknown_id_return_404() {
    let reg = Arc::new(MachineRegistry::new());
    let (_wire, admin) = fixture(reg);
    let id = "99".repeat(32);

    let (s, _) = admin_post(&admin, &id, "expire", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = admin_post(&admin, &id, "logout", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = admin_post(
        &admin,
        &id,
        "rename",
        serde_json::json!({ "hostname": "x" }),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = admin_post(&admin, &id, "tags", serde_json::json!({ "tags": [] })).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let s = admin_delete(&admin, &id).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_verbs_require_bearer_auth() {
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("aa".repeat(32), mk_record(0xaa, "n", 1, false));
    let (_wire, admin) = fixture(reg);

    // No bearer header at all.
    let router = admin_router(admin);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/machines/{}/logout", "aa".repeat(32)))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn map_touches_last_seen() {
    let reg = Arc::new(MachineRegistry::new());
    let r = mk_record(0xab, "node-touch", 30, false);
    let initial = r.last_seen;
    reg.upsert("ab".repeat(32), r);
    let (wire, _admin) = fixture(reg.clone());

    // Sleep briefly so the wall-clock advances.
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    let (s, _) = wire_map(&wire, &"ab".repeat(32)).await;
    assert_eq!(s, StatusCode::OK);
    let after = reg.get(&"ab".repeat(32)).unwrap().last_seen;
    assert!(after > initial, "/map should bump last_seen");
}

#[tokio::test]
async fn gc_ephemeral_removes_stale_devices() {
    let reg = Arc::new(MachineRegistry::new());
    let mut stale = mk_record(0xc0, "ephem-stale", 40, true);
    stale.last_seen = chrono::Utc::now() - chrono::Duration::seconds(300);
    reg.upsert("c0".repeat(32), stale);
    let fresh = mk_record(0xc1, "ephem-fresh", 41, true);
    reg.upsert("c1".repeat(32), fresh);
    let non_ephem = mk_record(0xc2, "perm", 42, false);
    reg.upsert("c2".repeat(32), non_ephem);

    let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
    assert_eq!(removed, vec!["c0".repeat(32)]);
    assert!(reg.get(&"c0".repeat(32)).is_none());
    assert!(reg.get(&"c1".repeat(32)).is_some());
    assert!(reg.get(&"c2".repeat(32)).is_some());
}

#[tokio::test]
async fn gc_ephemeral_leaves_fresh_devices() {
    let reg = Arc::new(MachineRegistry::new());
    let r = mk_record(0xd0, "ephem", 50, true);
    reg.upsert("d0".repeat(32), r);
    let removed = reg.gc_ephemeral(std::time::Duration::from_mins(1));
    assert!(removed.is_empty());
}

#[tokio::test(start_paused = true)]
async fn ephemeral_gc_task_runs_periodically() {
    // Use a very short interval — the task uses `tokio::time::interval`
    // which honours the paused runtime clock. `Utc::now()` is wall-clock
    // and doesn't pause, so we set `last_seen` deep into the past
    // (5 minutes ago) and use a 1ms grace so the first sweep finds it.
    let reg = Arc::new(MachineRegistry::new());
    let mut stale = mk_record(0xe0, "ephem-old", 60, true);
    stale.last_seen = chrono::Utc::now() - chrono::Duration::seconds(300);
    reg.upsert("e0".repeat(32), stale);

    let handle = headscale_api::tailscale_wire::spawn_ephemeral_gc(
        reg.clone(),
        std::time::Duration::from_millis(10),
        std::time::Duration::from_millis(1),
    );

    // Advance virtual time past the first tick (skipped) + second
    // (sweep). Yield repeatedly so the spawned task can run the body.
    for _ in 0..50 {
        tokio::time::advance(std::time::Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        if reg.get(&"e0".repeat(32)).is_none() {
            break;
        }
    }
    assert!(
        reg.get(&"e0".repeat(32)).is_none(),
        "background GC must remove stale ephemeral within a few ticks"
    );
    handle.abort();
}

#[tokio::test]
async fn forced_tags_override_registration() {
    // Direct upsert mirrors a register that landed with empty tags;
    // admin then sets forced_tags. The DTO reflects the override.
    let reg = Arc::new(MachineRegistry::new());
    reg.upsert("f0".repeat(32), mk_record(0xf0, "node-prod", 70, false));
    let (_wire, admin) = fixture(reg.clone());
    let (s, _) = admin_post(
        &admin,
        &"f0".repeat(32),
        "tags",
        serde_json::json!({ "tags": ["tag:override"] }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, v) = admin_get(&admin, &"f0".repeat(32)).await;
    assert_eq!(v["tags"][0], "tag:override");
}
