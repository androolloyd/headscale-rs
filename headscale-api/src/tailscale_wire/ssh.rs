use std::{collections::HashMap, time::Instant};

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::RngCore;
use serde::Deserialize;

use super::{
    AuthWaitOutcome, MachineRecord, SshCheckBinding, WireState, noise::NoisePeerMachineKey,
    wire::SshAction,
};
use crate::policy::SshPolicyNode;

const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const AUTH_ID_RANDOM_BYTES: usize = 18;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + 24;

#[derive(Debug, Deserialize)]
pub struct SshActionQuery {
    #[serde(default)]
    auth_id: Option<String>,
}

pub async fn handle_ssh_action(
    State(state): State<WireState>,
    Path((src_node_id, dst_node_id)): Path<(u64, u64)>,
    Query(query): Query<SshActionQuery>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
) -> Response {
    let Some(Extension(NoisePeerMachineKey(machine_key_hex))) = machine_key else {
        return ssh_error(StatusCode::UNAUTHORIZED, "missing Noise machine key");
    };

    let snapshot = state.machines.snapshot();
    let Some((_dst_key, dst_record)) = node_by_id(&snapshot, dst_node_id) else {
        return ssh_error(StatusCode::NOT_FOUND, "dst node not found");
    };
    if dst_record.machine_key_hex != machine_key_hex {
        return ssh_error(
            StatusCode::UNAUTHORIZED,
            "machine key does not match dst node",
        );
    }

    let binding = SshCheckBinding {
        src_node_id,
        dst_node_id,
    };
    let ssh_nodes = ssh_policy_nodes_from_snapshot(&snapshot);
    let check_period = state
        .policy
        .ssh_check_period_for(&ssh_nodes, src_node_id, dst_node_id);

    if let Some(auth_id) = query.auth_id.as_deref() {
        return ssh_action_followup(state, auth_id, binding, check_period.is_some()).await;
    }

    if let Some(period) = check_period
        && !period.is_zero()
        && state
            .registration_cache
            .last_ssh_auth(binding, state.policy.updated_at())
            .and_then(|last| Instant::now().checked_duration_since(last))
            .is_some_and(|elapsed| elapsed < period)
    {
        return ssh_action_json(ssh_accept_action());
    }

    let raw_auth_id = new_auth_id();
    state
        .registration_cache
        .insert_ssh_check(raw_auth_id.clone(), binding);
    let auth_id = format!("{AUTH_ID_PREFIX}{raw_auth_id}");
    let base_url = state.public_control_url.as_deref().unwrap_or("");
    ssh_action_json(SshAction {
        hold_and_delegate: crate::policy::ssh::ssh_check_hold_url_with_auth(base_url, &auth_id),
        message: format!(
            "# Headscale SSH requires an additional check.\n\
             # To authenticate, visit: {}\n\
             # Authentication checked with Headscale SSH.\n",
            auth_url(base_url, &auth_id)
        ),
        ..SshAction::default()
    })
}

async fn ssh_action_followup(
    state: WireState,
    auth_id: &str,
    binding: SshCheckBinding,
    check_found: bool,
) -> Response {
    let Some(raw_auth_id) = auth_id_cache_key(auth_id) else {
        return ssh_error(StatusCode::BAD_REQUEST, "Invalid auth_id");
    };
    let Some(cached_binding) = state.registration_cache.ssh_binding(raw_auth_id) else {
        return ssh_error(StatusCode::BAD_REQUEST, "Invalid auth_id");
    };
    if cached_binding != binding {
        return ssh_error(
            StatusCode::UNAUTHORIZED,
            "src/dst pair does not match auth session",
        );
    }

    match state.registration_cache.wait_for_auth(raw_auth_id).await {
        AuthWaitOutcome::Accepted => {
            if check_found {
                state.registration_cache.record_ssh_auth(
                    binding,
                    Instant::now(),
                    state.policy.updated_at(),
                );
            }
            ssh_action_json(ssh_accept_action())
        }
        AuthWaitOutcome::Rejected(_) | AuthWaitOutcome::Expired => ssh_action_json(SshAction {
            reject: true,
            ..SshAction::default()
        }),
        AuthWaitOutcome::Missing => ssh_error(StatusCode::BAD_REQUEST, "Invalid auth_id"),
    }
}

fn ssh_accept_action() -> SshAction {
    SshAction {
        accept: true,
        allow_agent_forwarding: true,
        allow_local_port_forwarding: true,
        allow_remote_port_forwarding: true,
        ..SshAction::default()
    }
}

fn ssh_action_json(action: SshAction) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        Json(action),
    )
        .into_response()
}

fn ssh_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{message}\n"),
    )
        .into_response()
}

fn auth_id_cache_key(auth_id: &str) -> Option<&str> {
    auth_id
        .strip_prefix(AUTH_ID_PREFIX)
        .filter(|rest| auth_id.len() == AUTH_ID_LENGTH && rest.len() == 24)
}

fn new_auth_id() -> String {
    let mut raw = [0u8; AUTH_ID_RANDOM_BYTES];
    rand_core::OsRng.fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

fn auth_url(base_url: &str, auth_id: &str) -> String {
    if base_url.is_empty() {
        format!("/auth/{auth_id}")
    } else {
        format!("{}/auth/{auth_id}", base_url.trim_end_matches('/'))
    }
}

fn node_by_id(
    snapshot: &HashMap<String, MachineRecord>,
    node_id: u64,
) -> Option<(&str, &MachineRecord)> {
    snapshot
        .iter()
        .find(|(node_key, record)| record.stable_node_id_for_key(node_key) == node_id)
        .map(|(node_key, record)| (node_key.as_str(), record))
}

fn ssh_policy_nodes_from_snapshot(snapshot: &HashMap<String, MachineRecord>) -> Vec<SshPolicyNode> {
    snapshot
        .iter()
        .map(|(node_key, record)| SshPolicyNode {
            id: record.stable_node_id_for_key(node_key),
            user: if record.user.is_empty() {
                None
            } else {
                Some(record.user.clone())
            },
            addrs: record.address_strings(),
            tags: record.forced_tags.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        DerpMapStore, MachineRegistry, MapResponseDebugStore, PingTracker, RegistrationCache,
        RuntimeConfigSnapshot,
        noise::{ServerNoiseKey, inner_router},
        test_support::{MockIpAllocator, MockRedeemer},
        wire::DerpMap,
    };
    use axum::body::{Body, to_bytes};
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};
    use tempfile::tempdir;
    use tower::ServiceExt;

    const SRC_NODE_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const DST_NODE_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const SRC_MACHINE_KEY: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DST_MACHINE_KEY: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn fixture() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let state = WireState {
            server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: DerpMapStore::shared(DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: Some("https://headscale.example".into()),
            runtime_config: Arc::new(RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(RegistrationCache::new()),
            pings: Arc::new(PingTracker::new()),
            mapresponse_debug: Arc::new(MapResponseDebugStore::disabled()),
        };
        insert_node(&state, SRC_NODE_KEY, SRC_MACHINE_KEY, "alice", "client", 10);
        insert_node(&state, DST_NODE_KEY, DST_MACHINE_KEY, "alice", "server", 20);
        let raw_policy = r#"{
          "ssh": [{
            "action": "check",
            "src": ["alice@"],
            "dst": ["autogroup:self"],
            "users": ["root"]
          }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.into(),
        );
        (state, dir)
    }

    fn insert_node(
        state: &WireState,
        node_key: &str,
        machine_key: &str,
        user: &str,
        hostname: &str,
        ip: u8,
    ) {
        state.machines.upsert(
            node_key.to_string(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.to_string(),
                machine_key.to_string(),
                user.to_string(),
                hostname.to_string(),
                Ipv4Addr::new(100, 64, 0, ip),
                false,
            ),
        );
    }

    fn request(uri: String, machine_key: &str) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key.to_string()));
        req
    }

    #[tokio::test]
    async fn ssh_action_initial_returns_bound_hold_and_auth_url() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state.clone())
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(!action.accept);
        assert!(!action.reject);
        assert!(
            action
                .hold_and_delegate
                .contains("/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID")
        );
        assert!(action.hold_and_delegate.contains("auth_id=hskey-authreq-"));
        assert!(
            action
                .message
                .contains("https://headscale.example/auth/hskey-authreq-")
        );
    }

    #[tokio::test]
    async fn ssh_action_followup_accepts_after_cli_approval() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
            },
        );

        let app = inner_router(state.clone());
        let waiter = tokio::spawn(async move {
            app.oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(state.registration_cache.approve_without_node(raw_auth_id));

        let resp = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(action.accept);
        assert!(!action.reject);
        assert!(action.allow_agent_forwarding);
    }

    #[tokio::test]
    async fn ssh_action_followup_accepts_already_approved_auth_id() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
            },
        );
        assert!(state.registration_cache.approve_without_node(raw_auth_id));

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(action.accept);
        assert!(!action.reject);
    }

    #[tokio::test]
    async fn ssh_action_rejects_wrong_dst_machine_key() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}"),
                SRC_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"machine key does not match dst node\n");
    }

    #[tokio::test]
    async fn ssh_action_rejects_auth_id_binding_mismatch() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src + 1,
                dst_node_id: dst,
            },
        );

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"src/dst pair does not match auth session\n");
    }

    #[tokio::test]
    async fn ssh_action_auto_approval_is_bound_to_policy_generation() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let binding = SshCheckBinding {
            src_node_id: src,
            dst_node_id: dst,
        };
        state.registration_cache.record_ssh_auth(
            binding,
            Instant::now(),
            state.policy.updated_at(),
        );

        let resp = inner_router(state.clone())
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(action.accept);

        let raw_policy = r#"{
          "ssh": [{
            "action": "check",
            "src": ["alice@"],
            "dst": ["autogroup:self"],
            "users": ["root"]
          }]
        }"#;
        state.policy.set_at(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.into(),
            state.policy.updated_at().unwrap_or_default() + 1,
        );

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(!action.accept);
        assert!(action.hold_and_delegate.contains("auth_id=hskey-authreq-"));
    }
}
