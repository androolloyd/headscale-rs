use std::{net::Ipv4Addr, sync::Arc};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use headscale_api::{
    dns::DnsStore,
    tailscale_wire::{
        AllocError, DerpMap, IpAllocator, KnockConfig, MachineRecord, MachineRegistry,
        PreauthRedeemer, RedeemError, RedeemOk, RegistrationCache, ServerNoiseKey, WireState,
    },
};
use tower::ServiceExt;

struct RejectingPreauth;

#[async_trait]
impl PreauthRedeemer for RejectingPreauth {
    async fn redeem(&self, _key: &str) -> Result<RedeemOk, RedeemError> {
        Err(RedeemError::Unknown)
    }
}

struct FixedIpAllocator;

impl IpAllocator for FixedIpAllocator {
    fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 42))
    }
}

fn wire_state() -> (WireState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
        preauth: Arc::new(RejectingPreauth),
        ip_allocator: Arc::new(FixedIpAllocator),
        machines: Arc::new(MachineRegistry::new()),
        registration_store: None,
        derp_map: headscale_api::tailscale_wire::DerpMapStore::shared(DerpMap::default()),
        native_derp: None,
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock: KnockConfig::disabled(),
        dns: Arc::new(DnsStore::new()),
        public_control_url: None,
        runtime_config: Arc::new(headscale_api::tailscale_wire::RuntimeConfigSnapshot::default()),
        registration_cache: Arc::new(RegistrationCache::new()),
        pings: Arc::new(headscale_api::tailscale_wire::PingTracker::new()),
        mapresponse_debug: Arc::new(
            headscale_api::tailscale_wire::MapResponseDebugStore::disabled(),
        ),
    };
    (state, dir)
}

#[tokio::test]
async fn derpverifyendpoint() {
    let (state, _dir) = wire_state();
    let node_key = "31".repeat(32);
    state.machines.upsert(
        node_key.clone(),
        MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            "41".repeat(32),
            "alice".into(),
            "derp-verified".into(),
            Ipv4Addr::new(100, 64, 0, 31),
            false,
        ),
    );

    let app = headscale_api::tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"NodePublic\":\"nodekey:{node_key}\",\"Source\":\"203.0.113.10\"}}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(&body[..], b"{\"Allow\":true}\n");
}
