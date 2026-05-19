//! End-to-end tests for the admin client surface.
//!
//! Each test spins up an `httpmock` MockServer, drives an `AdminClient`
//! against it, and asserts both the wire shape (method / path /
//! Authorization header / JSON body) and the decoded result. The mock
//! server runs on an ephemeral port — no shared state between tests
//! so they parallelise.

use headscale_cli::admin::{client::AdminClient, AdminError};
use httpmock::prelude::*;
use serde_json::json;

fn mk_client(server: &MockServer) -> AdminClient {
    AdminClient::new(server.base_url(), "secret-token")
}

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn users_list_decodes_array() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET)
                .path("/api/v1/users")
                .header("authorization", "Bearer secret-token");
            then.status(200).json_body(json!([
                {"name":"alice","created_at":1,"last_activity":2},
                {"name":"bob","created_at":3,"last_activity":4}
            ]));
        })
        .await;
    let client = mk_client(&s);
    let v: Vec<headscale_api::admin::UserRecord> = client.get_json("/users").await.unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].name, "alice");
}

#[tokio::test]
async fn users_create_posts_json_body() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(POST)
                .path("/api/v1/users")
                .header("authorization", "Bearer secret-token")
                .json_body(json!({"name": "alice"}));
            then.status(201)
                .json_body(json!({"name":"alice","created_at":1,"last_activity":1}));
        })
        .await;
    let client = mk_client(&s);
    let body = serde_json::json!({"name":"alice"});
    let rec: headscale_api::admin::UserRecord =
        client.post_json("/users", &body).await.unwrap();
    assert_eq!(rec.name, "alice");
}

#[tokio::test]
async fn users_delete_204() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(DELETE)
                .path("/api/v1/users/alice")
                .header("authorization", "Bearer secret-token");
            then.status(204);
        })
        .await;
    let client = mk_client(&s);
    client.delete_no_content("/users/alice").await.unwrap();
}

#[tokio::test]
async fn users_delete_404_maps_to_not_found() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(DELETE).path("/api/v1/users/ghost");
            then.status(404).json_body(json!({"error":"user 'ghost' does not exist"}));
        })
        .await;
    let client = mk_client(&s);
    let e = client.delete_no_content("/users/ghost").await.unwrap_err();
    assert!(matches!(e, AdminError::NotFound(_)));
}

// ---------------------------------------------------------------------------
// machines / nodes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn machines_list_decodes() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/machines");
            then.status(200).json_body(json!([
                {
                    "id": "aa".repeat(32),
                    "name": "node-1",
                    "user": "alice",
                    "ipv4": "100.64.0.5",
                    "online": true,
                    "last_seen": 1,
                    "machine_key_hex": "bb".repeat(32),
                    "os": "linux",
                    "version": "1.78.0",
                    "tags": [],
                    "routes": [],
                    "expired": false
                }
            ]));
        })
        .await;
    let client = mk_client(&s);
    let nodes: Vec<headscale_api::admin::MachineAdminRecord> =
        client.get_json("/machines").await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "node-1");
}

#[tokio::test]
async fn machines_get_one() {
    let s = MockServer::start_async().await;
    let id = "aa".repeat(32);
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path(format!("/api/v1/machines/{id}"));
            then.status(200).json_body(json!({
                "id": "aa".repeat(32),
                "name": "node-1",
                "user": "alice",
                "ipv4": "100.64.0.5",
                "online": true,
                "last_seen": 1,
                "machine_key_hex": "bb".repeat(32),
                "os": "linux",
                "version": "1.78.0",
                "tags": [],
                "routes": [],
                "expired": false
            }));
        })
        .await;
    let client = mk_client(&s);
    let path = format!("/machines/{id}");
    let node: headscale_api::admin::MachineAdminRecord =
        client.get_json(&path).await.unwrap();
    assert_eq!(node.user, "alice");
}

#[tokio::test]
async fn machines_expire_posts() {
    let s = MockServer::start_async().await;
    let id = "aa".repeat(32);
    let _m = s
        .mock_async(|when, then| {
            when.method(POST).path(format!("/api/v1/machines/{id}/expire"));
            then.status(204);
        })
        .await;
    let client = mk_client(&s);
    let path = format!("/machines/{id}/expire");
    client.post_no_content(&path).await.unwrap();
}

#[tokio::test]
async fn machines_delete() {
    let s = MockServer::start_async().await;
    let id = "aa".repeat(32);
    let _m = s
        .mock_async(|when, then| {
            when.method(DELETE).path(format!("/api/v1/machines/{id}"));
            then.status(204);
        })
        .await;
    let client = mk_client(&s);
    let path = format!("/machines/{id}");
    client.delete_no_content(&path).await.unwrap();
}

// ---------------------------------------------------------------------------
// preauthkeys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preauth_list_decodes() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/preauthkeys");
            then.status(200).json_body(json!([
                {
                    "key":"octrapreauth-aabbccdd00112233",
                    "user":"alice",
                    "created_at":1,
                    "expires_at":2,
                    "reusable":false,
                    "ephemeral":false,
                    "tags":[],
                    "redemptions":0
                }
            ]));
        })
        .await;
    let client = mk_client(&s);
    let keys: Vec<headscale_api::admin::PreauthAdminKey> =
        client.get_json("/preauthkeys").await.unwrap();
    assert_eq!(keys[0].user, "alice");
}

#[tokio::test]
async fn preauth_mint_posts_body() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(POST)
                .path("/api/v1/preauthkeys")
                .json_body(json!({
                    "user":"alice",
                    "ttl_secs": 86400_u64,
                    "reusable": true,
                    "ephemeral": false,
                    "tags":["tag:dev"]
                }));
            then.status(201).json_body(json!({
                "key":"octrapreauth-aabbccdd00112233",
                "user":"alice",
                "created_at":10,
                "expires_at": 86410_u64,
                "reusable":true,
                "ephemeral":false,
                "tags":["tag:dev"],
                "redemptions":0
            }));
        })
        .await;
    let client = mk_client(&s);
    let body = headscale_api::admin::PreauthMintRequest {
        user: "alice".into(),
        ttl_secs: 86_400,
        reusable: true,
        ephemeral: false,
        tags: vec!["tag:dev".into()],
    };
    let k: headscale_api::admin::PreauthAdminKey =
        client.post_json("/preauthkeys", &body).await.unwrap();
    assert_eq!(k.user, "alice");
    assert!(k.reusable);
}

#[tokio::test]
async fn preauth_expire_by_prefix() {
    let s = MockServer::start_async().await;
    let prefix = "octrapreauth-aabbccdd";
    let _m = s
        .mock_async(|when, then| {
            when.method(POST)
                .path(format!("/api/v1/preauthkeys/{prefix}/expire"));
            then.status(204);
        })
        .await;
    let client = mk_client(&s);
    let path = format!("/preauthkeys/{prefix}/expire");
    client.post_no_content(&path).await.unwrap();
}

// ---------------------------------------------------------------------------
// policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_get_returns_object() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/policy");
            then.status(200)
                .json_body(json!({"loaded": false, "policy": null}));
        })
        .await;
    let client = mk_client(&s);
    let v: serde_json::Value = client.get_json("/policy").await.unwrap();
    assert_eq!(v["loaded"], false);
}

#[tokio::test]
async fn policy_put_accepts_raw_text() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(PUT)
                .path("/api/v1/policy")
                .body("{\"acls\":[]}");
            then.status(202)
                .json_body(json!({"applied": false, "note": "stub"}));
        })
        .await;
    let client = mk_client(&s);
    let v = client
        .put_text("/policy", "{\"acls\":[]}".to_string())
        .await
        .unwrap();
    assert_eq!(v["applied"], false);
    assert_eq!(v["note"], "stub");
}

#[test]
fn policy_check_local_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.hujson");
    std::fs::write(
        &path,
        b"// comment\n{\n  \"acls\": [],\n}\n",
    )
    .unwrap();
    headscale_cli::admin::policy::check(&path).unwrap();
}

#[test]
fn policy_check_local_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.hujson");
    std::fs::write(&path, b"not json {").unwrap();
    let e = headscale_cli::admin::policy::check(&path).unwrap_err();
    assert!(matches!(e, AdminError::Local(_)));
}

// ---------------------------------------------------------------------------
// tailnet
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tailnet_status_decodes() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/tailnet");
            then.status(200).json_body(json!({
                "derp_regions": 3,
                "dns": {"magic_dns": false, "enabled": true},
                "policy_loaded": false
            }));
        })
        .await;
    let client = mk_client(&s);
    let v: serde_json::Value = client.get_json("/tailnet").await.unwrap();
    assert_eq!(v["derp_regions"], 3);
}

// ---------------------------------------------------------------------------
// auth + transport-level error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_401_maps_to_auth_error() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/users");
            then.status(401).json_body(json!({"error":"bad token"}));
        })
        .await;
    let client = mk_client(&s);
    let e = client
        .get_json::<serde_json::Value>("/users")
        .await
        .unwrap_err();
    assert!(matches!(e, AdminError::Auth(_)));
    assert_eq!(
        e.exit_code() as i32,
        headscale_cli::admin::ExitCode::Auth as i32
    );
}

#[tokio::test]
async fn server_500_maps_to_server_error() {
    let s = MockServer::start_async().await;
    let _m = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/users");
            then.status(500).body("boom");
        })
        .await;
    let client = mk_client(&s);
    let e = client
        .get_json::<serde_json::Value>("/users")
        .await
        .unwrap_err();
    assert!(matches!(e, AdminError::Server { status: 500, .. }));
}

#[tokio::test]
async fn connection_refused_maps_to_connection_error() {
    // Bind a listener to grab an ephemeral port, then drop the
    // listener so nobody is accepting on that port. The kernel will
    // reset / refuse the next SYN to it — the cleanest "no TCP
    // server" signal we can synthesise from inside the process.
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let url = format!("http://{addr}");
    let client = AdminClient::new(url, "t");
    let e = client
        .get_json::<serde_json::Value>("/users")
        .await
        .unwrap_err();
    assert!(
        matches!(e, AdminError::Connection(_)),
        "expected Connection error, got: {e:?}"
    );
    assert_eq!(
        e.exit_code() as i32,
        headscale_cli::admin::ExitCode::Connection as i32
    );
}

#[tokio::test]
async fn url_building_uses_api_v1_prefix() {
    // Sanity-check: every request must go to `/api/v1/...`, not
    // `/admin/...`.
    let s = MockServer::start_async().await;
    let hit = s
        .mock_async(|when, then| {
            when.method(GET).path("/api/v1/tailnet");
            then.status(200).json_body(json!({"derp_regions": 0}));
        })
        .await;
    let client = mk_client(&s);
    let _: serde_json::Value = client.get_json("/tailnet").await.unwrap();
    hit.assert_async().await;
}
