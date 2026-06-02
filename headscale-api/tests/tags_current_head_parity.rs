//! Focused current-head parity evidence for upstream
//! `integration/tags_test.go`.
//!
//! The generated backlog stubs live elsewhere; this file gives the
//! inventory exact normalized-name overlap with concrete Rust coverage.

#![cfg(feature = "admin")]

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    routing::post,
};
use chrono::{TimeZone, Utc};
use headscale_api::{
    admin::{
        AdminState, InMemoryPreauthAdmin, MachineAdmin, MachineAdminRecord, PersistentMachineAdmin,
        PersistentUserAdmin, UserAdmin, UserRegistry, WireMachineAdmin, router as admin_router,
    },
    policy::{PolicyStore, parse_hujson_policy, validate_requested_tags_for_node},
    tailscale_wire::{
        AllocError, DerpMap, DerpMapStore, IpAllocator, KnockConfig, MachineRecord,
        MachineRegistry, MapResponseDebugStore, PingTracker, PreauthRedeemer, RedeemError,
        RedeemOk, RegisterResponse, RegistrationCache, RuntimeConfigSnapshot, WireState,
        map as wire_map_handlers,
        noise::{NoisePeerMachineKey, ServerNoiseKey},
        register as wire_register_handlers,
    },
};
use headscale_db::Database;
use parking_lot::RwLock;
use serde_json::json;
use tower::ServiceExt;

const BEARER: &str = "tags-current-head-parity";
const TAG_USER: &str = "taguser";

fn key(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn tags(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn assert_tags(actual: &[String], expected: &[&str]) {
    let mut actual = actual.to_vec();
    let mut expected = tags(expected);
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

fn tag_policy() -> PolicyStore {
    let raw = r#"{
        "tagOwners": {
            "tag:valid-owned": ["taguser@"],
            "tag:second": ["taguser@"],
            "tag:valid-unowned": ["other-user@"]
        },
        "acls": [
            {"action":"accept","src":["*"],"dst":["*:*"]}
        ]
    }"#;
    let store = PolicyStore::new();
    store.set(
        parse_hujson_policy(raw).expect("tag policy parses"),
        raw.into(),
    );
    store
}

fn node_record(node_byte: u8, machine_byte: u8, user: &str, host: &str) -> MachineRecord {
    MachineRecord::new_at(
        Utc::now(),
        key(node_byte),
        key(machine_byte),
        user.into(),
        host.into(),
        Ipv4Addr::new(100, 64, 0, node_byte),
        false,
    )
}

fn admin_record(
    node_byte: u8,
    machine_byte: u8,
    user: &str,
    host: &str,
    tag_values: &[&str],
) -> MachineAdminRecord {
    MachineAdminRecord {
        node_id: 0,
        id: key(node_byte),
        name: host.into(),
        user: user.into(),
        user_id: None,
        auth_key_id: None,
        ipv4: Ipv4Addr::new(100, 64, 0, node_byte).to_string(),
        ipv6: None,
        online: true,
        last_seen: Utc::now().timestamp() as u64,
        created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap().timestamp() as u64,
        expiry: None,
        machine_key_hex: key(machine_byte),
        disco_key: String::new(),
        os: "linux".into(),
        version: "1.82.0".into(),
        tags: tags(tag_values),
        routes: Vec::new(),
        approved_routes: Vec::new(),
        register_method: 2,
        expired: false,
    }
}

fn admin_fixture(initial_tags: &[&str]) -> (Arc<MachineRegistry>, AdminState, String) {
    let registry = Arc::new(MachineRegistry::new());
    let node_key = key(0xa1);
    let mut record = node_record(0xa1, 0xb1, TAG_USER, "tag-node");
    record.forced_tags = tags(initial_tags);
    registry.upsert(node_key.clone(), record);

    let state = AdminState::builder()
        .bearer_token(BEARER)
        .users(UserRegistry::new())
        .machines(Arc::new(WireMachineAdmin::new(registry.clone())))
        .preauth(Arc::new(InMemoryPreauthAdmin::new()))
        .derp_regions(0)
        .policy(tag_policy())
        .build();

    (registry, state, node_key)
}

async fn admin_post_tags(
    admin: &AdminState,
    node_key: &str,
    tag_values: &[&str],
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/machines/{node_key}/tags"))
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "tags": tag_values })).unwrap(),
        ))
        .unwrap();
    let resp = admin_router(admin.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

fn assert_registry_tags(registry: &MachineRegistry, node_key: &str, expected: &[&str]) {
    let record = registry.get(node_key).expect("node exists");
    assert_tags(&record.forced_tags, expected);
}

#[derive(Clone, Default)]
struct TestRedeemer {
    keys: Arc<RwLock<HashMap<String, RedeemOk>>>,
}

impl TestRedeemer {
    fn insert(&self, key: &str, ok: RedeemOk) {
        self.keys.write().insert(key.into(), ok);
    }
}

#[async_trait]
impl PreauthRedeemer for TestRedeemer {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        self.keys
            .read()
            .get(key)
            .cloned()
            .ok_or(RedeemError::Unknown)
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        self.keys.read().get(key).cloned()
    }
}

#[derive(Default)]
struct SequentialIp {
    next: AtomicU8,
}

impl IpAllocator for SequentialIp {
    fn allocate(&self, _: &str) -> Result<Ipv4Addr, AllocError> {
        let host = self.next.fetch_add(1, Ordering::SeqCst) + 10;
        Ok(Ipv4Addr::new(100, 64, 0, host))
    }
}

fn wire_state(registry: Arc<MachineRegistry>, policy: PolicyStore) -> (WireState, TestRedeemer) {
    let dir = tempfile::tempdir().unwrap();
    let redeemer = TestRedeemer::default();
    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
        preauth: Arc::new(redeemer.clone()),
        ip_allocator: Arc::new(SequentialIp::default()),
        machines: registry,
        registration_store: None,
        derp_map: DerpMapStore::shared(DerpMap::default()),
        #[cfg(feature = "full")]
        native_derp: None,
        policy: Arc::new(policy),
        knock: KnockConfig::disabled(),
        dns: Arc::new(headscale_api::dns::DnsStore::new()),
        public_control_url: Some("https://headscale.example".into()),
        runtime_config: Arc::new(RuntimeConfigSnapshot::default()),
        registration_cache: Arc::new(RegistrationCache::new()),
        pings: Arc::new(PingTracker::new()),
        mapresponse_debug: Arc::new(MapResponseDebugStore::disabled()),
    };
    std::mem::forget(dir);
    (state, redeemer)
}

fn register_router(state: WireState) -> Router {
    Router::new()
        .route(
            "/machine/:node_key/register",
            post(wire_register_handlers::handle_register),
        )
        .with_state(state)
}

async fn register_with_auth_key(
    state: &WireState,
    node_byte: u8,
    machine_byte: u8,
    auth_key: &str,
    request_tags: &[&str],
) -> (StatusCode, serde_json::Value) {
    let node_key = key(node_byte);
    let machine_key = key(machine_byte);
    let mut hostinfo = json!({
        "Hostname": format!("node-{node_byte:02x}"),
    });
    if !request_tags.is_empty() {
        hostinfo["RequestTags"] = json!(request_tags);
    }
    let body = json!({
        "Version": 113,
        "NodeKey": format!("nodekey:{node_key}"),
        "Auth": { "AuthKey": auth_key },
        "Hostinfo": hostinfo,
        "Expiry": "2026-06-01T00:00:00Z"
    });
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/machine/nodekey:{node_key}/register"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(NoisePeerMachineKey(machine_key));
    let resp = register_router(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn register_ok(
    state: &WireState,
    node_byte: u8,
    machine_byte: u8,
    auth_key: &str,
    request_tags: &[&str],
) -> RegisterResponse {
    let (status, value) =
        register_with_auth_key(state, node_byte, machine_byte, auth_key, request_tags).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let response: RegisterResponse = serde_json::from_value(value).unwrap();
    assert!(response.machine_authorized);
    response
}

async fn register_rejected_requested_tags(
    state: &WireState,
    node_byte: u8,
    machine_byte: u8,
    auth_key: &str,
    request_tags: &[&str],
) {
    let (status, value) =
        register_with_auth_key(state, node_byte, machine_byte, auth_key, request_tags).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert!(
        value["error"]
            .as_str()
            .unwrap_or_default()
            .contains("requested tags"),
        "{value}"
    );
}

fn authkey_fixture(auth_key: &str, ok: RedeemOk) -> (WireState, Arc<MachineRegistry>) {
    let registry = Arc::new(MachineRegistry::new());
    let (state, redeemer) = wire_state(registry.clone(), tag_policy());
    redeemer.insert(auth_key, ok);
    (state, registry)
}

fn user_requested_tags_allowed(user: &str, requested: &[&str]) -> Result<Vec<String>, String> {
    let policy = tag_policy();
    let mut requested = tags(requested);
    validate_requested_tags_for_node(&policy, "100.64.0.77", user, &mut requested)?;
    Ok(requested)
}

async fn complete_user_registration(
    admin: &WireMachineAdmin,
    node_byte: u8,
    machine_byte: u8,
    user: &str,
    requested: &[&str],
) -> MachineAdminRecord {
    let requested = user_requested_tags_allowed(user, requested).expect("requested tags allowed");
    let mut pending = admin_record(
        node_byte,
        machine_byte,
        user,
        &format!("web-{node_byte:02x}"),
        &[],
    );
    pending.tags = requested;
    admin
        .complete_registration(pending, &tag_policy(), None)
        .await
        .unwrap()
        .record
}

fn map_router(state: WireState) -> Router {
    Router::new()
        .route(
            "/machine/:node_key/map",
            post(wire_map_handlers::handle_map),
        )
        .with_state(state)
}

async fn full_map_tags(
    state: &WireState,
    node_key: &str,
    machine_key: &str,
    request_tags: &[&str],
) -> Vec<String> {
    let mut body = json!({ "Version": 113 });
    if !request_tags.is_empty() {
        body["Hostinfo"] = json!({ "RequestTags": request_tags });
    }
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(format!("/machine/nodekey:{node_key}/map"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(NoisePeerMachineKey(machine_key.to_string()));
    let resp = map_router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["Node"]["Tags"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn tagsadminapicannotremovealltags() {
    let (registry, admin, node_key) = admin_fixture(&["tag:valid-owned"]);
    let (status, body) = admin_post_tags(&admin, &node_key, &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("cannot remove all tags")
    );
    assert_registry_tags(&registry, &node_key, &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsadminapicannotsetinvalidformat() {
    let (registry, admin, node_key) = admin_fixture(&["tag:valid-owned"]);
    let (status, body) = admin_post_tags(&admin, &node_key, &["invalid-no-prefix"]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("tag:"));
    assert_registry_tags(&registry, &node_key, &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsadminapicannotsetnonexistenttag() {
    let (registry, admin, node_key) = admin_fixture(&["tag:valid-owned"]);
    let (status, body) = admin_post_tags(&admin, &node_key, &["tag:nonexistent"]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("requested tags"));
    assert_registry_tags(&registry, &node_key, &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeyconverttouserviacliregister() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");
    let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
    users.create(TAG_USER).await.expect("create tag user");
    let admin = PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users);
    let preauth = headscale_db::preauth_keys::create_for_test(
        db.pool(),
        headscale_db::preauth_keys::CreateParams {
            user_id: String::new(),
            reusable: false,
            ephemeral: false,
            tags: tags(&["tag:valid-owned"]),
            expiration: None,
        },
    )
    .await
    .expect("create tags-only preauth row");

    let mut tagged = node_record(0xc1, 0xd1, "", "tags-only");
    tagged.forced_tags = tags(&["tag:valid-owned"]);
    let created = admin
        .create_or_update_auth_key_path(tagged.clone(), &tag_policy(), Some(preauth.row.id))
        .await
        .expect("tags-only auth-key registration")
        .record;
    assert_eq!(created.node_id, 1);
    assert!(created.user.is_empty());
    assert_tags(&created.tags, &["tag:valid-owned"]);

    let converted = admin
        .create_or_update_auth_path(
            admin_record(0xc2, 0xd1, TAG_USER, "user-owned", &[]),
            &tag_policy(),
        )
        .await
        .expect("CLI register converts existing tags-only node")
        .record;
    assert_eq!(converted.node_id, created.node_id);
    assert_eq!(converted.user, TAG_USER);
    assert!(converted.tags.is_empty());
    assert_eq!(converted.machine_key_hex, key(0xd1));
}

#[tokio::test]
async fn tagsauthkeywithtagadminoverridereauthpreserves() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-tagged",
        RedeemOk::for_user(TAG_USER).tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x11, 0x91, "hskey-auth-tagged", &[]).await;
    assert!(registry.set_forced_tags(&key(0x11), tags(&["tag:second"])));

    register_ok(&state, 0x12, 0x91, "hskey-auth-tagged", &[]).await;
    assert!(registry.get(&key(0x11)).is_none());
    assert_registry_tags(&registry, &key(0x12), &["tag:second"]);
}

#[tokio::test]
async fn tagsauthkeywithtagclicannotmodifyadmintags() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-tagged-admin",
        RedeemOk::for_user(TAG_USER).tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x13, 0x92, "hskey-auth-tagged-admin", &[]).await;
    assert!(registry.set_forced_tags(&key(0x13), tags(&["tag:valid-owned", "tag:second"])));

    register_rejected_requested_tags(
        &state,
        0x14,
        0x92,
        "hskey-auth-tagged-admin",
        &["tag:valid-owned"],
    )
    .await;
    assert_registry_tags(&registry, &key(0x13), &["tag:valid-owned", "tag:second"]);
}

#[tokio::test]
async fn tagsauthkeywithtagcannotaddviacli() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-no-add",
        RedeemOk::for_user(TAG_USER).tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x15, 0x93, "hskey-auth-no-add", &[]).await;

    register_rejected_requested_tags(
        &state,
        0x16,
        0x93,
        "hskey-auth-no-add",
        &["tag:valid-owned", "tag:second"],
    )
    .await;
    assert_registry_tags(&registry, &key(0x15), &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeywithtagcannotchangeviacli() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-no-change",
        RedeemOk::for_user(TAG_USER).tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x17, 0x94, "hskey-auth-no-change", &[]).await;

    register_rejected_requested_tags(&state, 0x18, 0x94, "hskey-auth-no-change", &["tag:second"])
        .await;
    assert_registry_tags(&registry, &key(0x17), &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeywithtagnoadvertiseflag() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-inherit",
        RedeemOk::for_user(TAG_USER).tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x19, 0x95, "hskey-auth-inherit", &[]).await;

    let record = registry.get(&key(0x19)).expect("registered node");
    assert_tags(&record.forced_tags, &["tag:valid-owned"]);
    assert!(
        record.expiry.is_none(),
        "tagged auth-key nodes do not expire"
    );
}

#[tokio::test]
async fn tagsauthkeywithouttagclicannotreduceadminmultitag() {
    let (state, registry) =
        authkey_fixture("hskey-auth-plain-reduce", RedeemOk::for_user(TAG_USER));
    register_ok(&state, 0x1a, 0x96, "hskey-auth-plain-reduce", &[]).await;
    assert!(registry.set_forced_tags(&key(0x1a), tags(&["tag:valid-owned", "tag:second"])));

    register_rejected_requested_tags(
        &state,
        0x1b,
        0x96,
        "hskey-auth-plain-reduce",
        &["tag:valid-owned"],
    )
    .await;
    assert_registry_tags(&registry, &key(0x1a), &["tag:valid-owned", "tag:second"]);
}

#[tokio::test]
async fn tagsauthkeywithouttagclinoopafteradminwithemptyadvertise() {
    let (state, registry) = authkey_fixture("hskey-auth-plain-empty", RedeemOk::for_user(TAG_USER));
    register_ok(&state, 0x1c, 0x97, "hskey-auth-plain-empty", &[]).await;
    assert!(registry.set_forced_tags(&key(0x1c), tags(&["tag:valid-owned"])));

    register_ok(&state, 0x1d, 0x97, "hskey-auth-plain-empty", &[]).await;
    assert_registry_tags(&registry, &key(0x1d), &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeywithouttagclinoopafteradminwithreset() {
    let (state, registry) = authkey_fixture("hskey-auth-plain-reset", RedeemOk::for_user(TAG_USER));
    register_ok(&state, 0x1e, 0x98, "hskey-auth-plain-reset", &[]).await;
    assert!(registry.set_forced_tags(&key(0x1e), tags(&["tag:valid-owned"])));

    register_ok(&state, 0x1f, 0x98, "hskey-auth-plain-reset", &[]).await;
    assert_registry_tags(&registry, &key(0x1f), &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeywithouttagcannotaddviacli() {
    let (state, registry) =
        authkey_fixture("hskey-auth-plain-no-add", RedeemOk::for_user(TAG_USER));
    register_ok(&state, 0x20, 0x99, "hskey-auth-plain-no-add", &[]).await;

    register_rejected_requested_tags(
        &state,
        0x21,
        0x99,
        "hskey-auth-plain-no-add",
        &["tag:valid-owned"],
    )
    .await;
    assert_registry_tags(&registry, &key(0x20), &[]);
}

#[tokio::test]
async fn tagsauthkeywithouttagregisternotags() {
    let (state, registry) = authkey_fixture("hskey-auth-plain", RedeemOk::for_user(TAG_USER));
    register_ok(&state, 0x22, 0x9a, "hskey-auth-plain", &[]).await;
    assert_registry_tags(&registry, &key(0x22), &[]);
}

#[tokio::test]
async fn tagsauthkeywithoutuserinheritstags() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-tags-only",
        RedeemOk::for_user("").tags(tags(&["tag:valid-owned"])),
    );
    register_ok(&state, 0x23, 0x9b, "hskey-auth-tags-only", &[]).await;
    let record = registry.get(&key(0x23)).expect("registered node");
    assert!(record.user.is_empty());
    assert_tags(&record.forced_tags, &["tag:valid-owned"]);
}

#[tokio::test]
async fn tagsauthkeywithoutuserrejectsadvertisedtags() {
    let (state, registry) = authkey_fixture(
        "hskey-auth-tags-only-reject",
        RedeemOk::for_user("").tags(tags(&["tag:valid-owned"])),
    );
    register_rejected_requested_tags(
        &state,
        0x24,
        0x9c,
        "hskey-auth-tags-only-reject",
        &["tag:second"],
    )
    .await;
    assert!(registry.get(&key(0x24)).is_none());
}

#[tokio::test]
async fn tagsissue2978reprotagreplacement() {
    let registry = Arc::new(MachineRegistry::new());
    let mut record = node_record(0x25, 0x9d, TAG_USER, "issue-2978");
    record.forced_tags = tags(&["tag:valid-owned"]);
    let node_key = record.node_key_hex.clone();
    let machine_key = record.machine_key_hex.clone();
    registry.upsert(node_key.clone(), record);
    registry.upsert(key(0x26), node_record(0x26, 0x9e, TAG_USER, "peer"));
    let (wire, _redeemer) = wire_state(registry.clone(), tag_policy());

    let initial = full_map_tags(&wire, &node_key, &machine_key, &[]).await;
    assert_tags(&initial, &["tag:valid-owned"]);
    assert!(registry.set_forced_tags(&node_key, tags(&["tag:second"])));
    let replaced = full_map_tags(&wire, &node_key, &machine_key, &[]).await;
    assert_tags(&replaced, &["tag:second"]);
}

#[tokio::test]
async fn tagsuserloginaddtagviaclireauth() {
    let registry = Arc::new(MachineRegistry::new());
    let admin = WireMachineAdmin::new(registry.clone());
    let first =
        complete_user_registration(&admin, 0x26, 0x9e, TAG_USER, &["tag:valid-owned"]).await;
    assert_tags(&first.tags, &["tag:valid-owned"]);

    let updated = complete_user_registration(
        &admin,
        0x27,
        0x9e,
        TAG_USER,
        &["tag:valid-owned", "tag:second"],
    )
    .await;
    assert!(!updated.tags.is_empty());
    assert_tags(&updated.tags, &["tag:valid-owned", "tag:second"]);
    assert_eq!(registry.len(), 1);
}

#[tokio::test]
async fn tagsuserloginclicannotremoveadmintags() {
    let registry = Arc::new(MachineRegistry::new());
    let mut record = node_record(0x28, 0x9f, TAG_USER, "admin-tags");
    record.forced_tags = tags(&["tag:valid-owned", "tag:second"]);
    let node_key = record.node_key_hex.clone();
    let machine_key = record.machine_key_hex.clone();
    registry.upsert(node_key.clone(), record);
    registry.upsert(key(0x2a), node_record(0x2a, 0xa1, TAG_USER, "peer"));
    let (wire, _redeemer) = wire_state(registry.clone(), tag_policy());

    let observed = full_map_tags(&wire, &node_key, &machine_key, &["tag:valid-owned"]).await;
    assert_tags(&observed, &["tag:valid-owned", "tag:second"]);
    assert_registry_tags(&registry, &node_key, &["tag:valid-owned", "tag:second"]);
}

#[tokio::test]
async fn tagsuserloginclinoopafteradminassignment() {
    let registry = Arc::new(MachineRegistry::new());
    let mut record = node_record(0x29, 0xa0, TAG_USER, "admin-wins");
    record.forced_tags = tags(&["tag:second"]);
    let node_key = record.node_key_hex.clone();
    let machine_key = record.machine_key_hex.clone();
    registry.upsert(node_key.clone(), record);
    registry.upsert(key(0x2b), node_record(0x2b, 0xa2, TAG_USER, "peer"));
    let (wire, _redeemer) = wire_state(registry.clone(), tag_policy());

    let observed = full_map_tags(&wire, &node_key, &machine_key, &["tag:valid-owned"]).await;
    assert_tags(&observed, &["tag:second"]);
    assert_registry_tags(&registry, &node_key, &["tag:second"]);
}

#[test]
fn tagsuserloginnonexistenttagatregistration() {
    let err = user_requested_tags_allowed(TAG_USER, &["tag:nonexistent"]).unwrap_err();
    assert!(err.contains("requested tags [tag:nonexistent]"));
}

#[tokio::test]
async fn tagsuserloginreauthwithemptytagsremovesalltags() {
    let registry = Arc::new(MachineRegistry::new());
    let admin = WireMachineAdmin::new(registry.clone());
    let first = complete_user_registration(
        &admin,
        0x2a,
        0xa1,
        TAG_USER,
        &["tag:valid-owned", "tag:second"],
    )
    .await;
    assert_tags(&first.tags, &["tag:valid-owned", "tag:second"]);

    let updated = complete_user_registration(&admin, 0x2b, 0xa1, TAG_USER, &[]).await;
    assert!(updated.tags.is_empty());
    assert_eq!(updated.user, TAG_USER);
    assert_eq!(registry.len(), 1);
}

#[tokio::test]
async fn tagsuserloginremovetagviaclireauth() {
    let registry = Arc::new(MachineRegistry::new());
    let admin = WireMachineAdmin::new(registry.clone());
    let first = complete_user_registration(
        &admin,
        0x2c,
        0xa2,
        TAG_USER,
        &["tag:valid-owned", "tag:second"],
    )
    .await;
    assert_tags(&first.tags, &["tag:valid-owned", "tag:second"]);

    let updated =
        complete_user_registration(&admin, 0x2d, 0xa2, TAG_USER, &["tag:valid-owned"]).await;
    assert_tags(&updated.tags, &["tag:valid-owned"]);
    assert_eq!(registry.len(), 1);
}
