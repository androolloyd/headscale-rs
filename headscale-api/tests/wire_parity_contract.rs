use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use async_trait::async_trait;
use axum::{Router, body::Body, http::StatusCode, response::Response, routing::post};
use headscale_api::tailscale_wire::wire::{
    DerpMap, DnsConfig, HostInfo, MapNode, MapResponse, RegisterAuth, RegisterRequest,
    RegisterResponse, SimpleLogin, SimpleUser,
};
use headscale_api::{
    WireState,
    tailscale_wire::{
        self, AllocError, IpAllocator, MachineRegistry, PreauthRedeemer, RedeemError, RedeemOk,
        ServerNoiseKey, noise::NoisePeerMachineKey, register as register_handlers,
    },
};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct ReplayRedeemer {
    available: Arc<Mutex<HashMap<String, RedeemOk>>>,
    used: Arc<Mutex<HashMap<String, RedeemOk>>>,
}

impl ReplayRedeemer {
    fn insert(&self, key: impl Into<String>, ok: RedeemOk) {
        let key = key.into();
        self.used.lock().remove(&key);
        self.available.lock().insert(key, ok);
    }
}

#[async_trait]
impl PreauthRedeemer for ReplayRedeemer {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        if let Some(ok) = self.available.lock().remove(key) {
            self.used.lock().insert(key.to_string(), ok.clone());
            return Ok(ok);
        }
        if self.used.lock().contains_key(key) {
            return Err(RedeemError::AlreadyUsed);
        }
        Err(RedeemError::Unknown)
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        self.available
            .lock()
            .get(key)
            .cloned()
            .or_else(|| self.used.lock().get(key).cloned())
    }
}

struct FixedIpAllocator;

impl IpAllocator for FixedIpAllocator {
    fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 42))
    }
}

fn wire_fixture() -> (WireState, ReplayRedeemer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let redeemer = ReplayRedeemer::default();
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(redeemer.clone()),
        ip_allocator: Arc::new(FixedIpAllocator),
        machines: Arc::new(MachineRegistry::new()),
        registration_store: None,
        derp_map: tailscale_wire::DerpMapStore::shared(DerpMap::default()),
        #[cfg(feature = "full")]
        native_derp: None,
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock: tailscale_wire::KnockConfig::disabled(),
        dns: Arc::new(headscale_api::dns::DnsStore::new()),
        public_control_url: None,
        runtime_config: Arc::new(tailscale_wire::RuntimeConfigSnapshot::default()),
        registration_cache: Arc::new(tailscale_wire::RegistrationCache::new()),
        pings: Arc::new(tailscale_wire::PingTracker::new()),
        mapresponse_debug: Arc::new(tailscale_wire::MapResponseDebugStore::disabled()),
    };
    (state, redeemer, dir)
}

fn machine_register_router(state: WireState) -> Router {
    Router::new()
        .route(
            "/machine/:node_key/register",
            post(register_handlers::handle_register),
        )
        .route(
            "/machine/register",
            post(register_handlers::handle_register_flat),
        )
        .with_state(state)
}

fn auth_register_body(node_key_hex: &str, authkey: &str, hostname: &str) -> Value {
    json!({
        "Version": 113,
        "NodeKey": format!("nodekey:{node_key_hex}"),
        "Auth": { "AuthKey": authkey },
        "Hostinfo": { "Hostname": hostname, "OS": "linux", "OSVersion": "6.8" },
    })
}

fn no_auth_register_body(node_key_hex: &str, hostname: &str) -> Value {
    json!({
        "Version": 113,
        "NodeKey": format!("nodekey:{node_key_hex}"),
        "Hostinfo": { "Hostname": hostname, "OS": "linux", "OSVersion": "6.8" },
    })
}

fn noise_post(
    uri: impl Into<String>,
    body: &Value,
    machine_key_hex: &str,
) -> axum::http::Request<Body> {
    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri(uri.into())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut()
        .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
    req
}

async fn decode_register_response(response: Response) -> RegisterResponse {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn json_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("object")
        .keys()
        .map(ToString::to_string)
        .collect();
    keys.sort();
    keys
}

#[test]
fn register_request_accepts_headscale_go_auth_key_shape() {
    let raw = json!({
        "NodeKey": "nodekey:012345",
        "Auth": { "AuthKey": "hskey-auth-deadbeef" },
        "Hostinfo": { "Hostname": "linux-a", "OS": "linux", "OSVersion": "6.8" },
        "Followup": "auth"
    });

    let req: RegisterRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.node_key, "nodekey:012345");
    assert_eq!(req.auth.unwrap().auth_key, "hskey-auth-deadbeef");
    assert_eq!(req.hostinfo.unwrap().os, "linux");
}

#[test]
fn register_response_uses_auth_url_and_id_acronyms() {
    let response = RegisterResponse {
        user: SimpleUser {
            id: 42,
            display_name: "Alice".into(),
            profile_pic_url: String::new(),
            created: None,
        },
        login: SimpleLogin {
            id: 42,
            provider: "preauth".into(),
            login_name: "alice@example.com".into(),
            display_name: "Alice".into(),
            profile_pic_url: String::new(),
        },
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: true,
        error: String::new(),
        node_key_signature: Some("cmVzcG9uc2Utc2lnbmF0dXJl".into()),
    };

    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["AuthURL"], "");
    assert!(value.get("AuthUrl").is_none());
    assert_eq!(value["NodeKeySignature"], "cmVzcG9uc2Utc2lnbmF0dXJl");
    assert_eq!(value["User"]["ID"], 42);
    assert!(value["User"].get("Id").is_none());
    assert_eq!(value["Login"]["ID"], 42);
}

#[test]
fn map_response_emits_required_stock_client_fields() {
    let response = MapResponse {
        node: Some(MapNode {
            id: 7,
            stable_id: "n7".into(),
            name: "linux-a.octra.test".into(),
            user: 42,
            key: "nodekey:aa".into(),
            machine: Some("mkey:bb".into()),
            addresses: vec!["100.64.0.7/32".into()],
            allowed_ips: vec!["100.64.0.7/32".into()],
            primary_routes: Vec::new(),
            hostinfo: HostInfo {
                hostname: "linux-a".into(),
                os: "linux".into(),
                os_version: "6.8".into(),
                routable_ips: Vec::new(),
                request_tags: Vec::new(),
                net_info: None,
                ..HostInfo::default()
            },
            created: None,
            key_expiry: None,
            cap: 0,
            tags: Vec::new(),
            last_seen: None,
            online: None,
            machine_authorized: true,
            capabilities: Vec::new(),
            cap_map: std::collections::BTreeMap::new(),
            expired: false,
            home_derp: 0,
            disco_key: Some("discokey:cc".into()),
            endpoints: vec!["198.51.100.7:41641".into()],
            ..MapNode::default()
        }),
        peers: Vec::new(),
        user_profiles: Vec::new(),
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(DerpMap::default()),
        domain: "octra.test".into(),
        keep_alive: true,
        packet_filter: Vec::new(),
        ssh_policy: None,
        ..MapResponse::default()
    };

    let value = serde_json::to_value(response).unwrap();
    let keys = json_keys(&value);
    for required in ["DERPMap", "DNSConfig", "Domain", "KeepAlive", "Node"] {
        assert!(keys.iter().any(|k| k == required), "missing {required}");
    }
    assert!(
        value.get("Peers").is_none(),
        "empty Peers follows upstream omitempty"
    );
    assert!(value.get("DerpMap").is_none());
    assert!(value.get("DnsConfig").is_none());
    assert_eq!(value["Node"]["ID"], 7);
    assert_eq!(value["Node"]["AllowedIPs"], json!(["100.64.0.7/32"]));
    assert_eq!(value["Node"]["DiscoKey"], "discokey:cc");
}

#[test]
fn register_auth_empty_default_still_serializes_auth_key() {
    let value = serde_json::to_value(RegisterAuth::default()).unwrap();
    assert_eq!(value, json!({ "AuthKey": "" }));
}

#[tokio::test]
async fn noise_register_rejects_used_authkey_replay_from_different_machine_key() {
    let (state, redeemer, _dir) = wire_fixture();
    let authkey = "hskey-auth-replay-bound-to-noise-machine";
    redeemer.insert(authkey, RedeemOk::for_user("alice").auth_key_id(28));
    let app = machine_register_router(state.clone());
    let node_key_hex = "41".repeat(32);
    let original_machine_key = "aa".repeat(32);
    let attacker_machine_key = "bb".repeat(32);

    let first = app
        .clone()
        .oneshot(noise_post(
            format!("/machine/nodekey:{node_key_hex}/register"),
            &auth_register_body(&node_key_hex, authkey, "original-host"),
            &original_machine_key,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = decode_register_response(first).await;
    assert!(first.machine_authorized);
    assert!(first.error.is_empty());

    let replay = app
        .clone()
        .oneshot(noise_post(
            format!("/machine/nodekey:{node_key_hex}/register"),
            &auth_register_body(&node_key_hex, authkey, "attacker-host"),
            &attacker_machine_key,
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = decode_register_response(replay).await;
    assert!(!replay.machine_authorized);
    assert_eq!(replay.error, "preauth key already used");

    let stored = state.machines.get(&node_key_hex).unwrap();
    assert_eq!(stored.machine_key_hex, original_machine_key);
    assert_eq!(stored.hostname, "original-host");

    let same_identity_replay = app
        .oneshot(noise_post(
            format!("/machine/nodekey:{node_key_hex}/register"),
            &auth_register_body(&node_key_hex, authkey, "legitimate-restart"),
            &original_machine_key,
        ))
        .await
        .unwrap();
    assert_eq!(same_identity_replay.status(), StatusCode::OK);
    let same_identity_replay = decode_register_response(same_identity_replay).await;
    assert!(same_identity_replay.machine_authorized);
    assert!(same_identity_replay.error.is_empty());

    let stored = state.machines.get(&node_key_hex).unwrap();
    assert_eq!(stored.machine_key_hex, original_machine_key);
    assert_eq!(stored.hostname, "legitimate-restart");
    assert_eq!(state.machines.len(), 1);
}

#[tokio::test]
async fn noise_flat_register_no_auth_restart_rejects_mismatched_machine_key() {
    let (state, redeemer, _dir) = wire_fixture();
    let authkey = "hskey-auth-flat-restart-machine-mismatch";
    redeemer.insert(authkey, RedeemOk::for_user("alice").auth_key_id(29));
    let app = machine_register_router(state.clone());
    let node_key_hex = "42".repeat(32);
    let original_machine_key = "cc".repeat(32);
    let attacker_machine_key = "dd".repeat(32);

    let first = app
        .clone()
        .oneshot(noise_post(
            "/machine/register",
            &auth_register_body(&node_key_hex, authkey, "flat-original"),
            &original_machine_key,
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = decode_register_response(first).await;
    assert!(first.machine_authorized);
    assert!(first.error.is_empty());

    let stolen_restart = app
        .oneshot(noise_post(
            "/machine/register",
            &no_auth_register_body(&node_key_hex, "flat-attacker"),
            &attacker_machine_key,
        ))
        .await
        .unwrap();
    assert_eq!(stolen_restart.status(), StatusCode::OK);
    let stolen_restart = decode_register_response(stolen_restart).await;
    assert!(!stolen_restart.machine_authorized);
    assert_eq!(
        stolen_restart.error,
        "node exists with a different machine key"
    );

    let stored = state.machines.get(&node_key_hex).unwrap();
    assert_eq!(stored.machine_key_hex, original_machine_key);
    assert_eq!(stored.hostname, "flat-original");
    assert_eq!(state.machines.len(), 1);
}
