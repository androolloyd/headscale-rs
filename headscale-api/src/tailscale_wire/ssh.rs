use std::{collections::HashMap, time::Instant};

use axum::{
    Extension,
    extract::{RawQuery, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::RngCore;
use serde::Deserialize;

use super::{
    AuthRequestKind, AuthWaitOutcome, MachineRecord, SshCheckBinding, WireState,
    noise::{NoisePeerMachineKey, NoiseRequestCancellation},
    wire::SshAction,
};
use crate::policy::{SshForwarding, SshPolicyNode};

const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const AUTH_ID_RANDOM_BYTES: usize = 24;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + 24;

#[derive(Debug, Deserialize)]
pub struct SshActionQuery {
    #[serde(default)]
    auth_id: Option<String>,
    #[serde(default)]
    local_user: Option<String>,
    /// URL.Query preserves byte strings even when the public projection
    /// cannot represent them. These never pass through lossy UTF-8 decoding.
    #[serde(skip)]
    raw_auth_id: Option<Vec<u8>>,
    #[serde(skip)]
    raw_local_user: Option<Vec<u8>>,
}

impl SshActionQuery {
    fn auth_id_bytes(&self) -> Option<&[u8]> {
        self.raw_auth_id
            .as_deref()
            .or_else(|| self.auth_id.as_deref().map(str::as_bytes))
            .filter(|value| !value.is_empty())
    }

    fn local_user_bytes(&self) -> &[u8] {
        self.raw_local_user
            .as_deref()
            .or_else(|| self.local_user.as_deref().map(str::as_bytes))
            .unwrap_or_default()
    }
}

pub(crate) async fn handle_ssh_action(
    State(state): State<WireState>,
    uri: Uri,
    RawQuery(raw_query): RawQuery,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    cancellation: Option<Extension<NoiseRequestCancellation>>,
) -> Response {
    let (src_node_id, dst_node_id) = match path_node_ids(uri.path()) {
        Ok(ids) => ids,
        Err(response) => return response,
    };
    let Some(Extension(NoisePeerMachineKey(machine_key_hex))) = machine_key else {
        return ssh_error(StatusCode::UNAUTHORIZED, "missing Noise machine key");
    };

    let snapshot = state.machines.snapshot_with_metadata();
    let Some((_dst_key, dst_record)) = node_by_id(&snapshot, dst_node_id) else {
        return ssh_error(StatusCode::NOT_FOUND, "dst node not found");
    };
    if dst_record.machine_key_hex != machine_key_hex {
        return ssh_error(
            StatusCode::UNAUTHORIZED,
            "machine key does not match dst node",
        );
    }

    let query = parse_query(raw_query.as_deref().unwrap_or_default());
    let local_user = query.local_user_bytes().to_vec();

    let binding = SshCheckBinding {
        src_node_id,
        dst_node_id,
        local_user: std::str::from_utf8(&local_user)
            .unwrap_or_default()
            .to_owned(),
    };
    let ssh_nodes = ssh_policy_nodes_from_snapshot(&state.machines, &snapshot);
    let forwarding = state.policy.ssh_forwarding();
    let cached_action = state.policy.with_ssh_check_period_for_bytes(
        &ssh_nodes,
        src_node_id,
        dst_node_id,
        &local_user,
        |period, stamp| match period {
            None => Some(ssh_action_json(&ssh_no_check_action(forwarding))),
            Some(period) if query.auth_id_bytes().is_none() && !period.is_zero() => state
                .registration_cache
                .last_ssh_auth_with_stamp(&binding, &stamp)
                .and_then(|last| Instant::now().checked_duration_since(last))
                .filter(|elapsed| *elapsed < period)
                .map(|_| ssh_action_json(&ssh_accept_action(forwarding))),
            _ => None,
        },
    );
    if let Some(action) = cached_action {
        return action;
    }

    if let Some(auth_id) = query.auth_id_bytes() {
        return ssh_action_followup(
            state,
            auth_id,
            binding.clone(),
            local_user,
            cancellation.map(|Extension(cancellation)| cancellation),
        )
        .await;
    }

    ssh_action_hold(&state, binding, &local_user)
}

fn path_node_ids(path: &str) -> Result<(u64, u64), Response> {
    // Chi routes URL.RawPath when it differs from the canonical escaped
    // Path. Do not decode percent-encoded IDs through Axum's UTF-8 Path.
    let rest = path
        .rsplit_once("/ssh/action/")
        .map_or("", |(_, rest)| rest);
    let (source, destination) = rest.split_once("/to/").unwrap_or((rest, ""));
    let source = parse_node_id(source)
        .ok_or_else(|| ssh_error(StatusCode::BAD_REQUEST, "Invalid src_node_id"))?;
    let destination = parse_node_id(destination)
        .ok_or_else(|| ssh_error(StatusCode::BAD_REQUEST, "Invalid dst_node_id"))?;
    Ok((source, destination))
}

fn parse_node_id(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn parse_query(raw: &str) -> SshActionQuery {
    let auth_id = super::query::first_value(raw, "auth_id").filter(|value| !value.is_empty());
    let local_user = super::query::first_value(raw, "local_user");
    SshActionQuery {
        auth_id: auth_id
            .as_deref()
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned),
        local_user: local_user
            .as_deref()
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned),
        raw_auth_id: auth_id,
        raw_local_user: local_user,
    }
}

fn ssh_action_hold(state: &WireState, binding: SshCheckBinding, local_user: &[u8]) -> Response {
    let base_url = state.public_control_url.as_deref().unwrap_or("");
    let target = match super::ssh_url::DelegationUrl::parse(base_url) {
        Ok(target) => target,
        Err(error) => {
            tracing::error!(%error, "parsing SSH action URL");
            return ssh_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let raw_auth_id = match new_auth_id() {
        Ok(auth_id) => auth_id,
        Err(error) => {
            tracing::error!(%error, "generating SSH auth ID");
            return ssh_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error");
        }
    };
    let auth_id = format!("{AUTH_ID_PREFIX}{raw_auth_id}");
    let hold_url = target.with_auth(&auth_id, local_user);
    state
        .registration_cache
        .insert_ssh_check(raw_auth_id, binding);
    ssh_action_json(&SshAction {
        hold_and_delegate: hold_url,
        message: format!(
            "# Headscale SSH requires an additional check.\n\
             # To authenticate, visit: {}\n\
             # Authentication checked with Headscale SSH.\n",
            auth_url(base_url, &auth_id)
        ),
        ..state.policy.ssh_forwarding().base_action()
    })
}

async fn ssh_action_followup(
    state: WireState,
    auth_id: &[u8],
    binding: SshCheckBinding,
    local_user: Vec<u8>,
    cancellation: Option<NoiseRequestCancellation>,
) -> Response {
    let Some(raw_auth_id) = auth_id_cache_key(auth_id) else {
        return ssh_error(StatusCode::BAD_REQUEST, "Invalid auth_id");
    };
    // All generated and public cache keys are UTF-8 Strings. A shape-valid
    // byte ID outside that domain is necessarily a missing session.
    let Ok(raw_auth_id) = std::str::from_utf8(raw_auth_id) else {
        return ssh_action_hold(&state, binding, &local_user);
    };
    let cached_binding = match state.registration_cache.auth_request_kind(raw_auth_id) {
        Some(AuthRequestKind::SshCheck(binding)) => binding,
        Some(AuthRequestKind::Registration) => {
            return ssh_error(StatusCode::BAD_REQUEST, "auth session is not for SSH check");
        }
        None => return ssh_action_hold(&state, binding, &local_user),
    };
    if !cached_binding.matches_pair(&binding) {
        return ssh_error(
            StatusCode::UNAUTHORIZED,
            "src/dst pair does not match auth session",
        );
    }

    let wait = state.registration_cache.wait_for_ssh_auth(raw_auth_id);
    let outcome = if let Some(cancellation) = cancellation {
        tokio::select! {
            outcome = wait => outcome,
            () = cancellation.cancelled() => {
                return ssh_error(StatusCode::UNAUTHORIZED, "ssh action follow-up cancelled");
            }
        }
    } else {
        wait.await
    };

    match outcome {
        AuthWaitOutcome::Accepted => {
            let snapshot = state.machines.snapshot_with_metadata();
            let ssh_nodes = ssh_policy_nodes_from_snapshot(&state.machines, &snapshot);
            let forwarding = state.policy.ssh_forwarding();
            state.policy.with_ssh_check_period_for_bytes(
                &ssh_nodes,
                binding.src_node_id,
                binding.dst_node_id,
                &local_user,
                |period, stamp| {
                    if period.is_none() {
                        return ssh_action_json(&ssh_no_check_action(forwarding));
                    }
                    state.registration_cache.record_ssh_auth_with_stamp(
                        &binding,
                        Instant::now(),
                        stamp,
                    );
                    ssh_action_json(&ssh_accept_action(forwarding))
                },
            )
        }
        AuthWaitOutcome::Rejected(_) | AuthWaitOutcome::Expired => ssh_action_json(&SshAction {
            reject: true,
            ..state.policy.ssh_forwarding().base_action()
        }),
        AuthWaitOutcome::Missing => ssh_action_hold(&state, binding, &local_user),
    }
}

fn ssh_no_check_action(forwarding: SshForwarding) -> SshAction {
    SshAction {
        reject: true,
        message: "# Headscale SSH: no check rule in the tailnet policy covers this connection.\n"
            .into(),
        ..forwarding.base_action()
    }
}

fn ssh_accept_action(forwarding: SshForwarding) -> SshAction {
    SshAction {
        accept: true,
        ..forwarding.base_action()
    }
}

fn ssh_action_json(action: &SshAction) -> Response {
    let body = super::map_json::encode_ssh_action(action).unwrap_or_else(|error| {
        // The Go handler has already committed its 200 before Encode.
        tracing::error!(%error, "encoding SSH action response");
        Vec::new()
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        body,
    )
        .into_response()
}

fn ssh_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        format!("{message}\n"),
    )
        .into_response()
}

fn auth_id_cache_key(auth_id: &[u8]) -> Option<&[u8]> {
    auth_id
        .strip_prefix(AUTH_ID_PREFIX.as_bytes())
        .filter(|rest| auth_id.len() == AUTH_ID_LENGTH && rest.len() == 24)
}

fn new_auth_id() -> Result<String, rand_core::Error> {
    let mut raw = [0u8; AUTH_ID_RANDOM_BYTES];
    rand_core::OsRng.try_fill_bytes(&mut raw)?;
    Ok(URL_SAFE_NO_PAD.encode(raw)[..24].to_string())
}

fn auth_url(base_url: &str, auth_id: &str) -> String {
    if base_url.is_empty() {
        format!("/auth/{auth_id}")
    } else {
        format!(
            "{}/auth/{auth_id}",
            base_url.strip_suffix('/').unwrap_or(base_url)
        )
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

fn ssh_policy_nodes_from_snapshot(
    _machines: &super::MachineRegistry,
    snapshot: &super::MachineSnapshot,
) -> Vec<SshPolicyNode> {
    snapshot
        .iter()
        .map(|(node_key, record)| SshPolicyNode {
            id: record.stable_node_id_for_key(node_key),
            user_id: snapshot.policy_identity(record).0,
            user: snapshot.policy_identity(record).1,
            addrs: snapshot.policy_addresses(record),
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
            registration_gate: None,
            derp_map: DerpMapStore::shared(DerpMap::default()),
            #[cfg(feature = "full")]
            native_derp: None,
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

    fn request_without_noise(uri: String) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    async fn assert_text_response(resp: Response, status: StatusCode, body: &[u8]) {
        assert_eq!(resp.status(), status);
        let actual = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&actual[..], body);
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
                local_user: "root".into(),
            },
        );

        let app = inner_router(state.clone());
        let waiter = tokio::spawn(async move {
            app.oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
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
                local_user: "root".into(),
            },
        );
        assert!(state.registration_cache.approve_without_node(raw_auth_id));

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
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
    async fn ssh_action_rejects_login_without_current_check_rule() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=deploy"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(action.reject);
        assert!(action.hold_and_delegate.is_empty());
    }

    #[tokio::test]
    async fn ssh_action_consumed_verdict_redelegates() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
                local_user: "root".into(),
            },
        );
        assert!(state.registration_cache.approve_without_node(raw_auth_id));
        let uri = format!(
            "/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"
        );
        let first = inner_router(state.clone())
            .oneshot(request(uri.clone(), DST_MACHINE_KEY))
            .await
            .unwrap();
        let first: SshAction =
            serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
        assert!(first.accept);
        let replay = inner_router(state)
            .oneshot(request(uri, DST_MACHINE_KEY))
            .await
            .unwrap();
        let replay: SshAction =
            serde_json::from_slice(&to_bytes(replay.into_body(), 4096).await.unwrap()).unwrap();
        assert!(!replay.accept);
        assert!(replay.hold_and_delegate.contains("auth_id=hskey-authreq-"));
    }

    #[tokio::test]
    async fn ssh_action_denies_approval_after_rule_removed() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
                local_user: "root".into(),
            },
        );
        let app = inner_router(state.clone());
        let waiter = tokio::spawn(async move {
            app.oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        state.policy.set(
            crate::policy::parse_hujson_policy("{}").unwrap(),
            "{}".into(),
        );
        assert!(state.registration_cache.approve_without_node(raw_auth_id));
        let resp = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        let action: SshAction =
            serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        assert!(!action.accept);
        assert!(action.reject);
    }

    #[tokio::test]
    async fn ssh_action_followup_rejects_after_auth_denial() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        let binding = SshCheckBinding {
            src_node_id: src,
            dst_node_id: dst,
            local_user: "root".into(),
        };
        state
            .registration_cache
            .insert_ssh_check(raw_auth_id.into(), binding.clone());
        assert!(state.registration_cache.reject(raw_auth_id, "denied"));

        let resp = inner_router(state.clone())
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(!action.accept);
        assert!(action.reject);
        assert!(
            state
                .registration_cache
                .last_ssh_auth(&binding, state.policy.updated_at())
                .is_none(),
            "rejected auth must not seed check-period auto approval"
        );
    }

    #[tokio::test]
    async fn ssh_action_followup_cancellation_returns_upstream_error_without_consuming_session() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
                local_user: "root".into(),
            },
        );
        let cancellation = NoiseRequestCancellation::new();

        let app = inner_router(state.clone());
        let mut req = request(
            format!(
                "/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"
            ),
            DST_MACHINE_KEY,
        );
        req.extensions_mut().insert(cancellation.clone());
        let waiter = tokio::spawn(async move { app.oneshot(req).await.unwrap() });
        tokio::task::yield_now().await;
        cancellation.cancel();

        let resp = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"ssh action follow-up cancelled\n");
        assert_eq!(
            state.registration_cache.ssh_binding(raw_auth_id),
            Some(SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
                local_user: "root".into(),
            }),
            "client cancellation must not remove or reject the auth session"
        );
    }

    #[tokio::test]
    async fn ssh_action_rejects_missing_noise_machine_key() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state)
            .oneshot(request_without_noise(format!(
                "/machine/ssh/action/{src}/to/{dst}"
            )))
            .await
            .unwrap();

        assert_text_response(
            resp,
            StatusCode::UNAUTHORIZED,
            b"missing Noise machine key\n",
        )
        .await;
    }

    #[tokio::test]
    async fn ssh_action_rejects_unknown_dst_node() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let resp = inner_router(state.clone())
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/999999"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_text_response(resp, StatusCode::NOT_FOUND, b"dst node not found\n").await;
        assert_eq!(
            state.registration_cache.len(),
            0,
            "unknown destination must not create an auth session"
        );
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
    async fn ssh_action_rejects_invalid_auth_id_shape() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=not-prefixed"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_text_response(resp, StatusCode::BAD_REQUEST, b"Invalid auth_id\n").await;
    }

    #[tokio::test]
    async fn ssh_action_rejects_unknown_auth_id() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-abcdefghijklmnopqrstuvwx"),
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

    #[tokio::test]
    async fn ssh_action_rejects_registration_auth_id_like_headscale_go() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert(
            raw_auth_id.into(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                "3333333333333333333333333333333333333333333333333333333333333333".into(),
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
                String::new(),
                "pending-registration".into(),
                Ipv4Addr::new(100, 64, 0, 30),
                false,
            ),
        );

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_text_response(
            resp,
            StatusCode::BAD_REQUEST,
            b"auth session is not for SSH check\n",
        )
        .await;
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
                local_user: "root".into(),
            },
        );

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root&auth_id=hskey-authreq-{raw_auth_id}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"src/dst pair does not match auth session\n");
    }

    #[tokio::test]
    async fn ssh_action_followup_accepts_changed_local_user_for_same_pair_like_headscale_go() {
        let (state, _dir) = fixture();
        let raw_policy = r#"{
          "ssh": [{
            "action": "check",
            "src": ["alice@"],
            "dst": ["autogroup:self"],
            "users": ["root", "deploy"]
          }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.into(),
        );
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let raw_auth_id = "abcdefghijklmnopqrstuvwx";
        state.registration_cache.insert_ssh_check(
            raw_auth_id.into(),
            SshCheckBinding {
                src_node_id: src,
                dst_node_id: dst,
                local_user: "root".into(),
            },
        );
        assert!(state.registration_cache.approve_without_node(raw_auth_id));

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=deploy&auth_id=hskey-authreq-{raw_auth_id}"),
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
    async fn ssh_action_auto_approval_is_bound_to_policy_generation() {
        let (state, _dir) = fixture();
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let binding = SshCheckBinding {
            src_node_id: src,
            dst_node_id: dst,
            local_user: "root".into(),
        };
        state.registration_cache.record_ssh_auth_for_policy(
            &binding,
            Instant::now(),
            &state.policy,
        );

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
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=root"),
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

    #[tokio::test]
    async fn ssh_action_check_period_cache_is_bound_to_pair_not_local_user() {
        let (state, _dir) = fixture();
        let raw_policy = r#"{
          "ssh": [{
            "action": "check",
            "checkPeriod": "1h",
            "src": ["alice@"],
            "dst": ["autogroup:self"],
            "users": ["root", "deploy"]
          }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.into(),
        );
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let binding = SshCheckBinding {
            src_node_id: src,
            dst_node_id: dst,
            local_user: "root".into(),
        };
        state.registration_cache.record_ssh_auth_for_policy(
            &binding,
            Instant::now(),
            &state.policy,
        );

        let resp = inner_router(state)
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?local_user=deploy"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let action: SshAction = serde_json::from_slice(&body).unwrap();
        assert!(action.accept);
        assert!(!action.reject);
        assert!(action.hold_and_delegate.is_empty());
    }

    /// Replace the random auth id the server mints so two runs of the same
    /// request can be compared byte for byte.
    fn normalize_auth_ids(body: &str) -> String {
        let mut out = String::with_capacity(body.len());
        let mut rest = body;
        while let Some(at) = rest.find(AUTH_ID_PREFIX) {
            let (head, tail) = rest.split_at(at + AUTH_ID_PREFIX.len());
            out.push_str(head);
            out.push_str(&"X".repeat(AUTH_ID_RANDOM_BYTES));
            rest = &tail[AUTH_ID_RANDOM_BYTES.min(tail.len())..];
        }
        out.push_str(rest);
        out
    }

    async fn action_json(state: &WireState, query: &str) -> serde_json::Value {
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let resp = inner_router(state.clone())
            .oneshot(request(
                format!("/machine/ssh/action/{src}/to/{dst}?{query}"),
                DST_MACHINE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_str(&normalize_auth_ids(std::str::from_utf8(&body).unwrap())).unwrap()
    }

    /// One response of every dynamic check-mode action shape the handler can
    /// produce, in an order that keeps each of them reachable: hold-and-delegate,
    /// the no-check-rule reject, a denied follow-up, an approved follow-up and
    /// the cached auto-approval that the approval seeds.
    async fn dynamic_actions(state: &WireState) -> Vec<(&'static str, serde_json::Value)> {
        let src = state.machines.stable_node_id_for_key(SRC_NODE_KEY);
        let dst = state.machines.stable_node_id_for_key(DST_NODE_KEY);
        let binding = SshCheckBinding {
            src_node_id: src,
            dst_node_id: dst,
            local_user: "root".into(),
        };
        let mut out = vec![
            ("hold", action_json(state, "local_user=root").await),
            ("no-check", action_json(state, "local_user=deploy").await),
        ];

        let denied = "rrrrrrrrrrrrrrrrrrrrrrrr";
        state
            .registration_cache
            .insert_ssh_check(denied.into(), binding.clone());
        assert!(state.registration_cache.reject(denied, "denied"));
        out.push((
            "denied",
            action_json(
                state,
                &format!("local_user=root&auth_id=hskey-authreq-{denied}"),
            )
            .await,
        ));

        let approved = "aaaaaaaaaaaaaaaaaaaaaaaa";
        state
            .registration_cache
            .insert_ssh_check(approved.into(), binding);
        assert!(state.registration_cache.approve_without_node(approved));
        out.push((
            "approved",
            action_json(
                state,
                &format!("local_user=root&auth_id=hskey-authreq-{approved}"),
            )
            .await,
        ));
        out.push(("cached", action_json(state, "local_user=root").await));
        out
    }

    const FORWARDING_KEYS: [&str; 3] = [
        "allowAgentForwarding",
        "allowLocalPortForwarding",
        "allowRemotePortForwarding",
    ];

    fn forwarding_cases() -> [(&'static str, SshForwarding); 5] {
        [
            (
                "no agent forwarding",
                SshForwarding {
                    agent: false,
                    ..SshForwarding::default()
                },
            ),
            (
                "no local port forwarding",
                SshForwarding {
                    local_port: false,
                    ..SshForwarding::default()
                },
            ),
            (
                "no remote port forwarding",
                SshForwarding {
                    remote_port: false,
                    ..SshForwarding::default()
                },
            ),
            (
                "no forwarding at all",
                SshForwarding {
                    agent: false,
                    local_port: false,
                    remote_port: false,
                },
            ),
            ("explicit allow all", SshForwarding::ALLOW_ALL),
        ]
    }

    /// `want` with every key the operator turned off dropped: `false` is
    /// omitted from the wire form, so this is exactly what the restricted
    /// output must equal.
    fn without_cleared_flags(
        want: &serde_json::Value,
        forwarding: SshForwarding,
    ) -> serde_json::Value {
        let mut out = want.clone();
        let object = out.as_object_mut().unwrap();
        for (key, allowed) in FORWARDING_KEYS.into_iter().zip([
            forwarding.agent,
            forwarding.local_port,
            forwarding.remote_port,
        ]) {
            if !allowed {
                object.remove(key);
            }
        }
        out
    }

    #[tokio::test]
    async fn ssh_action_forwarding_defaults_match_headscale_go() {
        // hscontrol/noise.go sshAction starts every dynamic action, including
        // hold-and-delegate and both rejects, with all three flags set.
        let (state, _dir) = fixture();
        let actions = dynamic_actions(&state).await;
        assert_eq!(actions.len(), 5);
        for (name, action) in &actions {
            for key in FORWARDING_KEYS {
                assert_eq!(action[key], true, "{name} must carry {key} by default");
            }
        }
        assert_eq!(actions[0].1["accept"], serde_json::Value::Null);
        assert_eq!(actions[1].1["reject"], true);
        assert_eq!(actions[2].1["reject"], true);
        assert_eq!(actions[3].1["accept"], true);
        assert_eq!(actions[4].1["accept"], true);
    }

    #[tokio::test]
    async fn ssh_action_forwarding_opt_out_clears_only_the_chosen_flags() {
        let (state, _dir) = fixture();
        let default = dynamic_actions(&state).await;

        for (label, forwarding) in forwarding_cases() {
            let (state, _dir) = fixture();
            state.policy.set_ssh_forwarding(forwarding);
            let restricted = dynamic_actions(&state).await;
            assert_eq!(restricted.len(), default.len());
            for ((name, want), (_, got)) in default.iter().zip(&restricted) {
                assert_eq!(
                    got,
                    &without_cleared_flags(want, forwarding),
                    "{label}: {name} must differ from the default only in the cleared flags"
                );
            }
        }
    }

    async fn map_ssh_policy(state: &WireState) -> crate::tailscale_wire::wire::SshPolicy {
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{DST_NODE_KEY}/map"))
            .header("content-type", "application/json")
            .body(Body::from(br#"{"Version":113}"#.to_vec()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(DST_MACHINE_KEY.to_string()));
        let resp = inner_router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let map: crate::tailscale_wire::wire::MapResponse = serde_json::from_slice(&raw).unwrap();
        map.ssh_policy.expect("SSH policy present in map response")
    }

    fn set_policy(state: &WireState, raw: &str) {
        state
            .policy
            .set(crate::policy::parse_hujson_policy(raw).unwrap(), raw.into());
    }

    const MIXED_POLICY: &str = r#"{
      "ssh": [
        {"action": "accept", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["root"]},
        {"action": "check", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["deploy"]}
      ]
    }"#;

    const RELOADED_POLICY: &str = r#"{
      "ssh": [
        {"action": "accept", "src": ["alice@"], "dst": ["autogroup:self"],
         "users": ["autogroup:nonroot", "root"]},
        {"action": "check", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["deploy"]}
      ]
    }"#;

    #[tokio::test]
    async fn map_response_ssh_policy_honours_forwarding_opt_out_across_policy_reload() {
        let (state, _dir) = fixture();
        set_policy(&state, MIXED_POLICY);
        let default = map_ssh_policy(&state).await;
        let accept = default
            .rules
            .iter()
            .find(|rule| rule.action.accept)
            .expect("accept rule");
        assert!(accept.action.allow_agent_forwarding);
        assert!(accept.action.allow_local_port_forwarding);
        assert!(accept.action.allow_remote_port_forwarding);
        let check = default
            .rules
            .iter()
            .find(|rule| !rule.action.hold_and_delegate.is_empty())
            .expect("check rule");
        assert!(!check.action.allow_agent_forwarding);

        for (label, forwarding) in forwarding_cases() {
            let (state, _dir) = fixture();
            state.policy.set_ssh_forwarding(forwarding);
            set_policy(&state, MIXED_POLICY);
            let served = map_ssh_policy(&state).await;

            let mut want = default.clone();
            for rule in &mut want.rules {
                rule.action.allow_agent_forwarding &= forwarding.agent;
                rule.action.allow_local_port_forwarding &= forwarding.local_port;
                rule.action.allow_remote_port_forwarding &= forwarding.remote_port;
            }
            assert_eq!(served, want, "{label}: served SSHPolicy");

            // A policy reload recompiles every rule; the operator's choice is
            // server config and must survive it.
            set_policy(&state, RELOADED_POLICY);
            let reloaded = map_ssh_policy(&state).await;
            assert!(
                !reloaded.rules.is_empty(),
                "{label}: reloaded policy has rules"
            );
            for rule in reloaded.rules.iter().filter(|rule| rule.action.accept) {
                assert_eq!(
                    rule.action.allow_agent_forwarding, forwarding.agent,
                    "{label}: agent flag after reload"
                );
                assert_eq!(
                    rule.action.allow_local_port_forwarding, forwarding.local_port,
                    "{label}: local flag after reload"
                );
                assert_eq!(
                    rule.action.allow_remote_port_forwarding, forwarding.remote_port,
                    "{label}: remote flag after reload"
                );
            }
        }
    }

    #[tokio::test]
    async fn compiled_cache_path_applies_forwarding_opt_out() {
        // Production serves SSH policy from the per-node compile cache that
        // PolicyStore::from_initial_registry builds. The opt-out is applied
        // after that cache, so a policy compiled and cached before the
        // setting was installed is still narrowed when read.
        let (mut state, _dir) = fixture();
        // The native store resolves `alice@` through the user table, so the
        // nodes carry the user's id the way registered nodes do.
        for (node_key, machine_key, hostname, ip) in [
            (SRC_NODE_KEY, SRC_MACHINE_KEY, "client", 10),
            (DST_NODE_KEY, DST_MACHINE_KEY, "server", 20),
        ] {
            let mut record = MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.to_string(),
                machine_key.to_string(),
                "alice".to_string(),
                hostname.to_string(),
                Ipv4Addr::new(100, 64, 0, ip),
                false,
            );
            record.user_id = Some(1);
            state.machines.upsert(node_key.to_string(), record);
        }
        let alice = crate::policy::PolicyUser {
            id: 1,
            name: "alice".into(),
            email: String::new(),
            provider_identifier: None,
        };
        state.policy = Arc::new(
            crate::policy::PolicyStore::from_initial_registry(
                Some((MIXED_POLICY.to_string(), 1)),
                vec![alice],
                &state.machines,
            )
            .unwrap(),
        );
        let before = map_ssh_policy(&state).await;
        assert!(
            before
                .rules
                .iter()
                .any(|rule| rule.action.accept && rule.action.allow_agent_forwarding),
            "cache primed with the default policy"
        );

        state.policy.set_ssh_forwarding(SshForwarding {
            agent: false,
            local_port: true,
            remote_port: false,
        });
        let after = map_ssh_policy(&state).await;
        assert_eq!(after.rules.len(), before.rules.len());
        for rule in after.rules.iter().filter(|rule| rule.action.accept) {
            assert!(!rule.action.allow_agent_forwarding);
            assert!(rule.action.allow_local_port_forwarding);
            assert!(!rule.action.allow_remote_port_forwarding);
        }
    }
}
