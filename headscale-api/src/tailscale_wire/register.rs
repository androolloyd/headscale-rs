//! `POST /machine/{node_key}/register` — initial join handler.
//!
//! Validates a presented preauth key against [`PreauthMinter`],
//! allocates configured tailnet addresses for the new machine, persists the
//! `MachineRecord`, and returns a Tailscale-shaped
//! `RegisterResponse`.
//!
//! ## Decision log
//!
//! - **Path param vs body NodeKey: we trust the *body*.** Upstream
//!   Tailscale carries the same value in both places; if they
//!   disagree we reject as `InvalidBody`.
//! - **Error envelope:** matches Tailscale's documented
//!   `RegisterResponse{Error: ...}` body for registration auth
//!   failures over Noise. Unsupported client capability versions stay
//!   HTTP 400, matching upstream `rejectUnsupported`.
//! - **User ID derivation:** the upstream uses a database primary
//!   key. We don't have a DB, so we FNV-hash the user label. This is
//!   stable across requests for the same user but doesn't survive a
//!   user-label rename.

use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Decode a `RegisterRequest` from a raw body without requiring the
/// `Content-Type: application/json` header. Stock `tailscale up`
/// (via controlhttp over the noise tunnel) sends register payloads
/// with no `Content-Type` set, so the axum `Json` extractor rejects
/// them with HTTP 415. We use a `Bytes` extractor + manual
/// `serde_json::from_slice` to mirror what upstream's
/// `gorilla/mux`-routed handlers accept.
fn parse_register_body(raw: &[u8]) -> Result<RegisterRequest, RegisterBodyError> {
    serde_json::from_slice::<RegisterRequest>(raw).map_err(|e| RegisterBodyError {
        version: register_body_version(raw),
        error: e.to_string(),
    })
}

#[derive(Debug)]
struct RegisterBodyError {
    version: u32,
    error: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterRequestVersionOnly {
    #[serde(default)]
    version: u32,
}

fn register_body_version(raw: &[u8]) -> u32 {
    serde_json::from_slice::<RegisterRequestVersionOnly>(raw)
        .map(|req| req.version)
        .unwrap_or_default()
}

fn parse_register_or_go_error(raw: &[u8]) -> Result<RegisterRequest, axum::response::Response> {
    match parse_register_body(raw) {
        Ok(body) => Ok(body),
        Err(RegisterBodyError { version, error }) => {
            reject_unsupported_capability(version)?;
            Err(register_error_response(error))
        }
    }
}

use super::noise::{NoisePeerMachineKey, NoiseRequestCancellation};
use super::routes::{auto_approved_routes_for_node, normalize_advertised_routes};
use super::wire::{
    HostInfo, MapNode, RegisterRequest, RegisterResponse, SimpleLogin, SimpleUser,
    is_auto_derived_given_name, is_supported_capability_version, strip_key_prefix,
    unsupported_client_error,
};
use super::{MachineRecord, RedeemError, RegistrationWaitOutcome, WireState};

const REGISTRATION_ID_RANDOM_BYTES: usize = 18;
const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const REGISTRATION_ID_LENGTH: usize = 24;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + REGISTRATION_ID_LENGTH;
const REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH: &str =
    "node exists with a different machine key";
const REGISTER_LOGOUT_MACHINE_KEY_MISMATCH: &str = "node exist with different machine key";
pub(crate) const CAPABILITY_ADMIN: &str = "https://tailscale.com/cap/is-admin";
pub(crate) const CAPABILITY_DEFAULT_AUTO_UPDATE: &str = "default-auto-update";
pub(crate) const CAPABILITY_FILE_SHARING: &str = "https://tailscale.com/cap/file-sharing";
pub(crate) const CAPABILITY_SSH: &str = "https://tailscale.com/cap/ssh";

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub async fn handle_register(
    State(state): State<WireState>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    cancellation: Option<Extension<NoiseRequestCancellation>>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let body = match parse_register_or_go_error(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Err(resp) = reject_unsupported_capability(body.version) {
        return resp;
    }
    // Resolve hex form of the node key.
    let body_node_key_hex = match strip_key_prefix(&body.node_key) {
        Some(h) => h.to_string(),
        None => body.node_key.clone(),
    };
    let path_node_key_hex = match strip_key_prefix(&node_key_path) {
        Some(h) => h.to_string(),
        None => node_key_path.clone(),
    };
    if body_node_key_hex != path_node_key_hex {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "path node_key does not match body NodeKey".into(),
            }),
        )
            .into_response();
    }
    register_inner(
        state,
        body_node_key_hex,
        machine_key,
        body,
        cancellation.map(|Extension(cancellation)| cancellation),
    )
    .await
}

/// `POST /machine/register` (v1.78+ flat path).
///
/// Identical to [`handle_register`] except the NodeKey is read solely
/// from the request body — the URL carries no path parameter. Stock
/// `tailscale up` after the controlhttp forced-443 switchover posts to
/// this shape; the keyed `/machine/{node_key}/register` route is kept
/// for older clients and our own integration tests.
pub async fn handle_register_flat(
    State(state): State<WireState>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    cancellation: Option<Extension<NoiseRequestCancellation>>,
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let body = match parse_register_or_go_error(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    if let Err(resp) = reject_unsupported_capability(body.version) {
        return resp;
    }
    let body_node_key_hex = match strip_key_prefix(&body.node_key) {
        Some(h) => h.to_string(),
        None => body.node_key.clone(),
    };
    register_inner(
        state,
        body_node_key_hex,
        machine_key,
        body,
        cancellation.map(|Extension(cancellation)| cancellation),
    )
    .await
}

/// Shared logic between the keyed and flat register handlers.
///
/// `node_key_hex` is the canonical, prefix-stripped form. The body's
/// own NodeKey is also re-parsed here (and used to populate the
/// `MachineRecord`); callers are expected to have already validated
/// that the two agree (for the keyed path) or supplied the body's value
/// directly (for the flat path).
async fn register_inner(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    cancellation: Option<NoiseRequestCancellation>,
) -> axum::response::Response {
    let has_auth = body.auth.is_some();
    let authkey = body.auth.as_ref().map_or("", |a| a.auth_key.as_str());
    let requested_tags = requested_tags_for_body(&body);
    let now = chrono::Utc::now();
    let default_expiry = configured_node_expiry(state.runtime_config.as_ref(), now);

    if let Some(expiry) = body.expiry
        && !is_go_zero_expiry(expiry)
        && expiry <= now
        && let Some(record) = state.machines.get(&node_key_hex)
    {
        if let Err(resp) = validate_existing_machine_key(
            &machine_key_hex,
            &record,
            REGISTER_LOGOUT_MACHINE_KEY_MISMATCH,
        ) {
            return resp;
        }
        if record.is_expired_at(now) {
            return Json(node_key_expired_response(false)).into_response();
        }
        return logout_existing_node(&state, &node_key_hex, &record, expiry);
    }

    if authkey.is_empty() {
        if !has_auth && let Some(record) = state.machines.get(&node_key_hex) {
            if let Err(resp) = validate_existing_machine_key(
                &machine_key_hex,
                &record,
                REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH,
            ) {
                return resp;
            }
            if record.is_expired_at(now) {
                return Json(node_key_expired_response(false)).into_response();
            }
            if let Some(expiry) = body.expiry {
                if is_go_zero_expiry(expiry) {
                    return Json(register_response_for_record(&record)).into_response();
                } else if expiry > now {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorBody {
                            error: "extending key is not allowed".into(),
                        }),
                    )
                        .into_response();
                }
            } else {
                return Json(register_response_for_record(&record)).into_response();
            }
        }

        if body
            .followup
            .as_deref()
            .is_some_and(|followup| !followup.is_empty())
        {
            let registration_id = match registration_id_from_followup(
                body.followup
                    .as_deref()
                    .expect("checked non-empty followup"),
            ) {
                Ok(registration_id) => registration_id,
                Err(error) => {
                    return register_error_response(error.to_string());
                }
            };

            let outcome = {
                let registration_cache = state.registration_cache.clone();
                let wait = registration_cache.wait_for_registration(&registration_id);
                tokio::pin!(wait);
                if let Some(cancellation) = cancellation {
                    tokio::select! {
                        outcome = &mut wait => outcome,
                        () = cancellation.cancelled() => {
                            return register_error_response("registration timed out");
                        }
                    }
                } else {
                    wait.await
                }
            };

            match outcome {
                RegistrationWaitOutcome::Registered(record) => {
                    return Json(register_response_for_record(&record)).into_response();
                }
                RegistrationWaitOutcome::ApprovedWithoutNode
                | RegistrationWaitOutcome::Rejected(_)
                | RegistrationWaitOutcome::Expired
                | RegistrationWaitOutcome::Missing => {
                    return register_interactive(state, node_key_hex, machine_key_hex, body).await;
                }
            }
        }
        return register_interactive(state, node_key_hex, machine_key_hex, body).await;
    }

    let redeemed = match state.preauth.redeem(authkey).await {
        Ok(ok) => ok,
        Err(err) => {
            let Some(ok) = state.preauth.lookup(authkey).await else {
                return preauth_error_response(err);
            };
            let Some((existing_node_key, existing)) = state
                .machines
                .get_by_machine_key_for_user(&machine_key_hex, &ok.user)
            else {
                return preauth_error_response(err);
            };
            if existing_node_key != node_key_hex {
                return preauth_error_response(err);
            }
            if !failed_authkey_belongs_to_existing_node(&existing, ok.auth_key_id) {
                return preauth_error_response(err);
            }
            ok
        }
    };
    let user = redeemed.user.clone();

    if !requested_tags.is_empty() {
        return invalid_requested_tags_response(&requested_tags);
    }

    let RegisterHostInfoParts {
        mut host_info,
        hostname,
        os: requested_os,
        os_version: requested_os_version,
        available_routes,
        ssh_host_keys: requested_ssh_host_keys,
    } = match register_hostinfo_parts(&body) {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };

    let existing_machine = state
        .machines
        .get_by_machine_key_for_user(&machine_key_hex, &user);
    if state.registration_store.is_none()
        && let Some((old_node_key_hex, _)) = existing_machine.as_ref()
        && old_node_key_hex != &node_key_hex
        && let Some(existing_target) = state.machines.get(&node_key_hex)
        && (existing_target.machine_key_hex != machine_key_hex || existing_target.user != user)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "node key already exists".into(),
            }),
        )
            .into_response();
    }
    let (ipv4, ipv6) = if let Some((_, existing)) = existing_machine.as_ref() {
        (existing.ipv4, existing.ipv6)
    } else {
        match allocate_register_ips(&state, &format!("{user}:{node_key_hex}")) {
            Ok(ips) => ips,
            Err(resp) => return resp,
        }
    };
    let addr = policy_addr(ipv4, ipv6);
    let forced_tags = existing_machine.as_ref().map_or_else(
        || redeemed.tags.clone(),
        |(_, existing)| existing.forced_tags.clone(),
    );
    let approved_routes = match auto_approved_routes_for_node(
        &state.policy,
        &addr,
        Some(&user),
        &forced_tags,
        &[],
        &available_routes,
    ) {
        Ok(routes) => routes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("invalid approved routes: {e}"),
                }),
            )
                .into_response();
        }
    };
    let approved_routes = match existing_machine.as_ref() {
        Some((_, existing)) => merge_existing_approved_routes(
            &existing.approved_routes,
            &available_routes,
            approved_routes,
        ),
        None => approved_routes,
    };
    // P1 lifecycle: stamp `created_at` / `last_seen` at registration
    // time + propagate the preauth's `ephemeral` flag. `forced_tags`
    // adopts the preauth's tag list verbatim so the very first /map
    // call emits the operator's intended tags; later
    // `POST /api/v1/machines/{id}/tags` overrides on demand.
    let now = chrono::Utc::now();
    let created_at = existing_machine
        .as_ref()
        .map_or(now, |(_, existing)| existing.created_at);
    let ephemeral = existing_machine
        .as_ref()
        .map_or(redeemed.ephemeral, |(_, existing)| existing.ephemeral);
    let auth_key_id = redeemed.auth_key_id.or_else(|| {
        existing_machine
            .as_ref()
            .and_then(|(_, existing)| existing.auth_key_id)
    });
    let node_id = existing_machine
        .as_ref()
        .and_then(|(_, existing)| existing.node_id);
    let user_id = existing_machine
        .as_ref()
        .and_then(|(_, existing)| existing.user_id);
    let user_display_name = existing_machine
        .as_ref()
        .map_or_else(String::new, |(_, existing)| {
            existing.user_display_name.clone()
        });
    let user_profile_pic_url = existing_machine
        .as_ref()
        .map_or_else(String::new, |(_, existing)| {
            existing.user_profile_pic_url.clone()
        });
    let (disco_key, endpoints, home_derp) =
        existing_machine
            .as_ref()
            .map_or((None, Vec::new(), 0), |(_, existing)| {
                (
                    existing.disco_key.clone(),
                    existing.endpoints.clone(),
                    existing.home_derp,
                )
            });
    preserve_net_info_from_existing(
        &mut host_info,
        existing_machine.as_ref().map(|(_, existing)| existing),
    );
    let home_derp = host_info
        .net_info
        .as_ref()
        .map_or(home_derp, |net_info| net_info.preferred_derp);
    let ssh_host_keys = if requested_ssh_host_keys.is_empty() {
        existing_machine
            .as_ref()
            .map(|(_, existing)| existing.ssh_host_keys.clone())
            .unwrap_or_default()
    } else {
        requested_ssh_host_keys
    };
    let os = if requested_os.is_empty() {
        existing_machine
            .as_ref()
            .map(|(_, existing)| existing.os.clone())
            .unwrap_or_default()
    } else {
        requested_os
    };
    let os_version = if requested_os_version.is_empty() {
        existing_machine
            .as_ref()
            .map(|(_, existing)| existing.os_version.clone())
            .unwrap_or_default()
    } else {
        requested_os_version
    };
    let expiry = if forced_tags.is_empty() {
        effective_register_expiry(body.expiry, default_expiry, now)
    } else {
        None
    };
    let given_name = if let Some((_, existing)) = existing_machine.as_ref()
        && !is_auto_derived_given_name(&existing.hostname, &existing.host_info_for_node().hostname)
    {
        existing.hostname.clone()
    } else {
        state.machines.resolve_auto_given_name(
            &node_key_hex,
            &hostname,
            existing_machine
                .as_ref()
                .map(|(old_node_key, _)| old_node_key.as_str()),
        )
    };
    let rec = MachineRecord {
        node_id,
        auth_key_id,
        node_key_hex: node_key_hex.clone(),
        machine_key_hex,
        user,
        user_id,
        user_display_name,
        user_profile_pic_url,
        hostname: given_name,
        os,
        os_version,
        host_info,
        ipv4,
        ipv6,
        // Wall 7: DiscoKey + Endpoints arrive on the `/map` call, not
        // on register. New registrations start empty; same-machine
        // reauth preserves the last map-provided values.
        disco_key,
        endpoints,
        home_derp,
        expiry,
        last_seen: now,
        ephemeral,
        created_at,
        forced_tags,
        available_routes,
        approved_routes,
        ssh_host_keys,
        register_method: 1,
    };

    if let Some(store) = &state.registration_store {
        let saved = match store
            .create_or_update_auth_key_registration(
                rec.clone(),
                state.policy.as_ref(),
                redeemed.auth_key_id,
            )
            .await
        {
            Ok(saved) => saved,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: format!("persisting node registration failed: {error}"),
                    }),
                )
                    .into_response();
            }
        };
        if let Some(old_node_key_hex) = saved.replaced_node_key_hex.as_deref() {
            state.machines.replace_node_key_auth_completion(
                old_node_key_hex,
                saved.record.node_key_hex.clone(),
                saved.record,
            );
        } else {
            state
                .machines
                .upsert_auth_completion(saved.record.node_key_hex.clone(), saved.record);
        }
    } else if let Some((old_node_key_hex, _)) = existing_machine {
        state.machines.replace_node_key_auth_completion(
            &old_node_key_hex,
            node_key_hex.clone(),
            rec,
        );
    } else {
        state
            .machines
            .upsert_auth_completion(node_key_hex.clone(), rec);
    }

    let rec = state
        .machines
        .get(&node_key_hex)
        .expect("record was just inserted");
    Json(register_response_for_record(&rec)).into_response()
}

async fn register_interactive(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
) -> axum::response::Response {
    let RegisterHostInfoParts {
        host_info,
        hostname,
        os,
        os_version,
        available_routes,
        ssh_host_keys,
    } = match register_hostinfo_parts(&body) {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };
    let requested_tags = requested_tags_for_body(&body);
    let (ipv4, ipv6) = match allocate_register_ips(&state, &format!("pending:{node_key_hex}")) {
        Ok(ips) => ips,
        Err(resp) => return resp,
    };
    let now = chrono::Utc::now();
    let default_expiry = configured_node_expiry(state.runtime_config.as_ref(), now);
    let registration_id = new_registration_id();
    let expiry = if requested_tags.is_empty() {
        effective_register_expiry(body.expiry, default_expiry, now)
    } else {
        None
    };
    let record = MachineRecord {
        node_id: None,
        auth_key_id: None,
        node_key_hex,
        machine_key_hex,
        user: String::new(),
        user_id: None,
        user_display_name: String::new(),
        user_profile_pic_url: String::new(),
        hostname,
        os,
        os_version,
        host_info,
        ipv4,
        ipv6,
        disco_key: None,
        endpoints: Vec::new(),
        home_derp: 0,
        expiry,
        last_seen: now,
        ephemeral: body.ephemeral,
        created_at: now,
        forced_tags: requested_tags,
        available_routes,
        approved_routes: Vec::new(),
        ssh_host_keys,
        register_method: 0,
    };
    state
        .registration_cache
        .insert(registration_id.clone(), record);

    Json(RegisterResponse {
        user: empty_simple_user(),
        login: empty_simple_login(),
        node_key_expired: false,
        auth_url: auth_url_for_registration(&state, &registration_id),
        machine_authorized: false,
        error: String::new(),
        node_key_signature: None,
    })
    .into_response()
}

struct RegisterHostInfoParts {
    host_info: HostInfo,
    hostname: String,
    os: String,
    os_version: String,
    available_routes: Vec<String>,
    ssh_host_keys: Vec<String>,
}

fn register_hostinfo_parts(
    body: &RegisterRequest,
) -> Result<RegisterHostInfoParts, axum::response::Response> {
    let hostinfo = body.hostinfo.as_ref();
    let available_routes = body
        .hostinfo
        .as_ref()
        .map(|h| normalize_advertised_routes(&h.routable_ips))
        .transpose()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: format!("invalid Hostinfo.RoutableIPs: {e}"),
                }),
            )
                .into_response()
        })?
        .unwrap_or_default();
    let mut host_info = hostinfo.cloned().unwrap_or_default();
    host_info.routable_ips.clone_from(&available_routes);
    Ok(RegisterHostInfoParts {
        hostname: host_info.hostname.clone(),
        os: host_info.os.clone(),
        os_version: host_info.os_version.clone(),
        available_routes,
        ssh_host_keys: host_info.ssh_host_keys.clone(),
        host_info,
    })
}

fn preserve_net_info_from_existing(host_info: &mut HostInfo, existing: Option<&MachineRecord>) {
    if host_info.net_info.is_some() {
        return;
    }
    host_info.net_info = existing.and_then(|existing| existing.host_info_for_node().net_info);
}

fn requested_tags_for_body(body: &RegisterRequest) -> Vec<String> {
    body.hostinfo
        .as_ref()
        .map(|hostinfo| normalize_requested_tags(&hostinfo.request_tags))
        .unwrap_or_default()
}

fn normalize_requested_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn invalid_requested_tags_response(tags: &[String]) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: format!(
                "requested tags [{}] are invalid or not permitted",
                tags.join(" ")
            ),
        }),
    )
        .into_response()
}

fn merge_existing_approved_routes(
    existing_approved_routes: &[String],
    _available_routes: &[String],
    auto_approved_routes: Vec<String>,
) -> Vec<String> {
    let mut merged: BTreeSet<String> = existing_approved_routes.iter().cloned().collect();
    merged.extend(auto_approved_routes);
    merged.into_iter().collect()
}

fn configured_node_expiry(
    runtime_config: &crate::tailscale_wire::RuntimeConfigSnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    let nanos = runtime_config.node.expiry;
    if nanos <= 0 {
        return None;
    }
    let duration = chrono::Duration::nanoseconds(nanos);
    Some(
        now.checked_add_signed(duration)
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    )
}

fn effective_register_expiry(
    expiry: Option<chrono::DateTime<chrono::Utc>>,
    default_expiry: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    expiry.filter(|expiry| *expiry > now).or(default_expiry)
}

fn is_go_zero_expiry(expiry: chrono::DateTime<chrono::Utc>) -> bool {
    expiry
        == chrono::NaiveDate::from_ymd_opt(1, 1, 1)
            .expect("valid Go zero date")
            .and_hms_opt(0, 0, 0)
            .expect("valid Go zero time")
            .and_utc()
}

fn preauth_error_response(err: RedeemError) -> axum::response::Response {
    let error = match err {
        RedeemError::Unknown => "preauth key not recognised",
        RedeemError::Expired => "preauth key expired",
        RedeemError::AlreadyUsed => "preauth key already used",
    };
    register_error_response(error)
}

fn failed_authkey_belongs_to_existing_node(
    existing: &MachineRecord,
    presented_auth_key_id: Option<i64>,
) -> bool {
    match (existing.auth_key_id, presented_auth_key_id) {
        (Some(existing_auth_key_id), Some(presented_auth_key_id)) => {
            existing_auth_key_id == presented_auth_key_id
        }
        _ => true,
    }
}

fn logout_existing_node(
    state: &WireState,
    node_key_hex: &str,
    record: &MachineRecord,
    expiry: chrono::DateTime<chrono::Utc>,
) -> axum::response::Response {
    if record.ephemeral {
        state.machines.delete(node_key_hex);
        return Json(node_key_expired_response(false)).into_response();
    }

    state.machines.set_expiry(node_key_hex, Some(expiry));
    let updated = state.machines.get(node_key_hex).unwrap_or_else(|| {
        let mut updated = record.clone();
        updated.expiry = Some(expiry);
        updated
    });
    Json(register_response_for_record(&updated)).into_response()
}

fn require_noise_machine_key(
    machine_key: Option<Extension<NoisePeerMachineKey>>,
) -> Result<String, axum::response::Response> {
    let Some(Extension(NoisePeerMachineKey(machine_key))) = machine_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing Noise machine key".into(),
            }),
        )
            .into_response());
    };
    if machine_key.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing Noise machine key".into(),
            }),
        )
            .into_response());
    }
    Ok(machine_key)
}

fn validate_existing_machine_key(
    presented_machine_key_hex: &str,
    record: &MachineRecord,
    mismatch_error: &'static str,
) -> Result<(), axum::response::Response> {
    if record.machine_key_hex == presented_machine_key_hex {
        return Ok(());
    }

    Err(register_error_response(mismatch_error))
}

fn reject_unsupported_capability(version: u32) -> Result<(), axum::response::Response> {
    if is_supported_capability_version(version) {
        return Ok(());
    }
    Err(plain_register_error(
        StatusCode::BAD_REQUEST,
        &unsupported_client_error(version),
    ))
}

fn plain_register_error(status: StatusCode, message: &str) -> axum::response::Response {
    (status, format!("{message}\n")).into_response()
}

fn register_error_response(error: impl Into<String>) -> axum::response::Response {
    Json(RegisterResponse {
        user: empty_simple_user(),
        login: empty_simple_login(),
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: false,
        error: error.into(),
        node_key_signature: None,
    })
    .into_response()
}

fn allocate_register_ips(
    state: &WireState,
    alloc_input: &str,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), axum::response::Response> {
    let ipv4 = if state.ip_allocator.ipv4_enabled() {
        Some(state.ip_allocator.allocate(alloc_input).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("ip allocation failed: {e}"),
                }),
            )
                .into_response()
        })?)
    } else {
        None
    };
    let ipv6 = state.ip_allocator.allocate_ipv6(alloc_input).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("ip allocation failed: {e}"),
            }),
        )
            .into_response()
    })?;
    if ipv4.is_none() && ipv6.is_none() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: "ip allocation failed: no IP prefixes enabled".into(),
            }),
        )
            .into_response());
    }
    Ok((ipv4, ipv6))
}

fn policy_addr(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> String {
    ipv4.map(|addr| addr.to_string())
        .or_else(|| ipv6.map(|addr| addr.to_string()))
        .unwrap_or_default()
}

fn empty_simple_user() -> SimpleUser {
    SimpleUser {
        id: 0,
        display_name: String::new(),
        profile_pic_url: String::new(),
        created: None,
    }
}

fn empty_simple_login() -> SimpleLogin {
    SimpleLogin {
        id: 0,
        provider: String::new(),
        login_name: String::new(),
        display_name: String::new(),
        profile_pic_url: String::new(),
    }
}

fn node_key_expired_response(machine_authorized: bool) -> RegisterResponse {
    RegisterResponse {
        user: empty_simple_user(),
        login: empty_simple_login(),
        node_key_expired: true,
        auth_url: String::new(),
        machine_authorized,
        error: String::new(),
        node_key_signature: None,
    }
}

fn register_response_for_record(record: &MachineRecord) -> RegisterResponse {
    let profile = record.tailscale_user_profile();
    RegisterResponse {
        user: SimpleUser {
            id: profile.id,
            display_name: profile.display_name.clone(),
            profile_pic_url: profile.profile_pic_url.clone(),
            created: None,
        },
        login: SimpleLogin {
            id: profile.id,
            provider: if record.is_tagged() {
                String::new()
            } else if record.register_method == 3 {
                "oidc".into()
            } else if record.register_method == 2 {
                "cli".into()
            } else {
                "octravpn-preauth".into()
            },
            login_name: profile.login_name,
            display_name: profile.display_name,
            profile_pic_url: profile.profile_pic_url,
        },
        node_key_expired: record.is_expired_at(chrono::Utc::now()),
        auth_url: String::new(),
        machine_authorized: true,
        error: String::new(),
        node_key_signature: None,
    }
}

fn auth_url_for_registration(state: &WireState, registration_id: &str) -> String {
    let auth_id = format!("{AUTH_ID_PREFIX}{registration_id}");
    match state.public_control_url.as_deref() {
        Some(url) if !url.is_empty() => {
            format!("{}/register/{auth_id}", url.trim_end_matches('/'))
        }
        _ => format!("/register/{auth_id}"),
    }
}

fn registration_id_from_followup(followup: &str) -> Result<String, &'static str> {
    let without_query = followup.split_once('?').map_or(followup, |(path, _)| path);
    let path = without_query
        .split_once('#')
        .map_or(without_query, |(path, _)| path);
    let marker = "/register/";
    let Some((_, registration_id)) = path.rsplit_once(marker) else {
        return Err("invalid followup URL");
    };

    if registration_id.contains('/') {
        return Err("invalid registration ID");
    }

    registration_id_from_register_path(registration_id)
        .map(str::to_owned)
        .ok_or("invalid registration ID")
}

fn registration_id_from_register_path(segment: &str) -> Option<&str> {
    let rest = segment.strip_prefix(AUTH_ID_PREFIX)?;
    (segment.len() == AUTH_ID_LENGTH && rest.len() == REGISTRATION_ID_LENGTH).then_some(rest)
}

fn new_registration_id() -> String {
    let mut raw = [0u8; REGISTRATION_ID_RANDOM_BYTES];
    rand_core::OsRng.fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Helper exposed for tests + `/map`: turn a `MachineRecord` into the
/// `MapNode` shape we ship in `MapResponse.Peers`.
pub fn record_to_map_node(rec: &MachineRecord, domain: &str) -> MapNode {
    fn qualify(label: String, domain: &str) -> String {
        if domain.is_empty() {
            label
        } else {
            format!("{label}.{domain}.")
        }
    }

    let name = if rec.hostname.is_empty() {
        qualify(
            format!(
                "node-{}",
                &rec.node_key_hex[..8.min(rec.node_key_hex.len())]
            ),
            domain,
        )
    } else {
        qualify(rec.hostname.clone(), domain)
    };
    let id = rec.stable_node_id();
    let stable_id = id.to_string();
    // `User` mirrors upstream `tailcfg.Node.User`; tagged nodes use
    // headscale-go's synthetic TaggedDevices user instead of their
    // registering preauth-key user.
    let user = rec.tailscale_user_id();
    let machine = if rec.machine_key_hex.is_empty() {
        None
    } else {
        Some(format!("mkey:{}", rec.machine_key_hex))
    };
    let expired = rec.is_expired_at(chrono::Utc::now());
    let addresses = rec.address_prefixes();
    MapNode {
        id,
        stable_id,
        name,
        user,
        key: format!("nodekey:{}", rec.node_key_hex),
        machine,
        addresses: addresses.clone(),
        allowed_ips: addresses
            .into_iter()
            .chain(rec.approved_routes.iter().cloned())
            .collect(),
        primary_routes: rec.approved_routes.clone(),
        hostinfo: rec.host_info_for_node(),
        created: Some(rec.created_at),
        key_expiry: rec.expiry,
        cap: 0,
        tags: rec.forced_tags.clone(),
        last_seen: Some(rec.last_seen),
        online: Some(false),
        // Any non-expired record in [`MachineRegistry`] passed
        // [`PreauthRedeemer::redeem`]; expired self nodes must carry
        // the upstream unauthorized/expired combination so stock
        // clients transition back to `NeedsLogin`.
        machine_authorized: !expired,
        capabilities: Vec::new(),
        cap_map: default_node_cap_map(),
        expired,
        home_derp: rec.home_derp,
        legacy_derp_string: if rec.home_derp == 0 {
            String::new()
        } else {
            format!("127.3.3.40:{}", rec.home_derp)
        },
        // Wall 7: fan the client-provided DiscoKey + Endpoints back
        // out so `wgengine.Reconfig` materialises this peer. Empty /
        // None ⇒ omitted on the wire (see `skip_serializing_if` on
        // `MapNode.disco_key` + `MapNode.endpoints`).
        disco_key: rec.disco_key.clone(),
        endpoints: rec.endpoints.clone(),
        ..MapNode::default()
    }
}

fn default_node_cap_map() -> BTreeMap<String, Vec<serde_json::Value>> {
    BTreeMap::from([
        (CAPABILITY_ADMIN.to_string(), Vec::new()),
        (
            CAPABILITY_DEFAULT_AUTO_UPDATE.to_string(),
            vec![serde_json::Value::Bool(false)],
        ),
        (CAPABILITY_FILE_SHARING.to_string(), Vec::new()),
        (CAPABILITY_SSH.to_string(), Vec::new()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        AllocError, IpAllocator, MachineRegistrationStore, MachineRegistry,
        PersistedMachineRegistration, PreauthRedeemer, RedeemOk, WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        router_with_oidc,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use axum::body::to_bytes;
    use std::collections::BTreeMap;
    use std::{sync::Arc, time::Duration};
    use tempfile::tempdir;
    use tower::ServiceExt;

    const TEST_MACHINE_KEY_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn router(state: WireState) -> axum::Router {
        machine_router(state).layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                if req.extensions().get::<NoisePeerMachineKey>().is_none() {
                    req.extensions_mut()
                        .insert(NoisePeerMachineKey(TEST_MACHINE_KEY_HEX.to_string()));
                }
                next.run(req).await
            },
        ))
    }

    fn runtime_config_with_node_expiry(
        expiry: Duration,
    ) -> crate::tailscale_wire::RuntimeConfigSnapshot {
        let mut config = crate::tailscale_wire::RuntimeConfigSnapshot::default();
        config.node.expiry = i64::try_from(expiry.as_nanos()).unwrap_or(i64::MAX);
        config
    }

    fn fixture() -> (WireState, MockRedeemer, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let redeemer = MockRedeemer::new();
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(redeemer.clone()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            #[cfg(feature = "full")]
            native_derp: None,
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        };
        (state, redeemer, dir)
    }

    fn req_body(node_key_hex: &str, authkey: &str) -> serde_json::Value {
        serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Auth": { "AuthKey": authkey },
            "Hostinfo": { "Hostname": "peer-a", "OS": "linux", "OSVersion": "6.6" },
        })
    }

    fn oidc_runtime() -> crate::oidc::OidcAuthRuntime {
        crate::oidc::OidcAuthRuntime::new(crate::oidc::OidcAuthConfig {
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/oauth2/auth".into(),
            token_endpoint: "https://issuer.example/oauth2/token".into(),
            userinfo_endpoint: Some("https://issuer.example/oauth2/userinfo".into()),
            jwks_uri: "https://issuer.example/oauth2/jwks".into(),
            client_id: "headscale-rs".into(),
            client_secret: "secret".into(),
            redirect_url: "https://headscale.example/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            extra_params: BTreeMap::from([("domain_hint".into(), "example.com".into())]),
            pkce: crate::oidc::OidcPkceConfig {
                enabled: true,
                method: crate::oidc::OidcPkceMethod::S256,
            },
            policy: crate::oidc::OidcPolicyConfig::default(),
        })
    }

    #[derive(Default)]
    struct RecordingRegistrationStore {
        calls: parking_lot::Mutex<Vec<(MachineRecord, Option<i64>)>>,
    }

    #[async_trait::async_trait]
    impl MachineRegistrationStore for RecordingRegistrationStore {
        async fn create_or_update_auth_key_registration(
            &self,
            mut record: MachineRecord,
            _policy: &crate::policy::PolicyStore,
            auth_key_id: Option<i64>,
        ) -> Result<PersistedMachineRegistration, String> {
            self.calls.lock().push((record.clone(), auth_key_id));
            record.hostname = "persisted-peer".into();
            record.ipv4 = Some(Ipv4Addr::new(100, 64, 9, 9));
            Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: None,
            })
        }
    }

    struct Ipv6OnlyAllocator;

    impl IpAllocator for Ipv6OnlyAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Err(AllocError::Internal(
                "IPv4 allocator should not be called when disabled".into(),
            ))
        }

        fn ipv4_enabled(&self) -> bool {
            false
        }

        fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
            Ok(Some("fd7a:115c:a1e0::66".parse().unwrap()))
        }
    }

    #[test]
    fn record_to_map_node_emits_approved_routes() {
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            "aa".repeat(32),
            "bb".repeat(32),
            "alice".into(),
            "router-a".into(),
            Ipv4Addr::new(100, 64, 0, 8),
            false,
        );
        record.os = "linux".into();
        record.os_version = "6.8".into();
        record.available_routes = vec!["10.0.0.0/24".into(), "fd7a:115c:a1e0::/48".into()];
        record.approved_routes = vec!["10.0.0.0/24".into()];

        let node = record_to_map_node(&record, "octra.test");

        assert_eq!(node.name, "router-a.octra.test.");
        assert_eq!(node.allowed_ips, vec!["100.64.0.8/32", "10.0.0.0/24"]);
        assert_eq!(node.primary_routes, vec!["10.0.0.0/24"]);
        assert_eq!(
            node.hostinfo.routable_ips,
            vec!["10.0.0.0/24", "fd7a:115c:a1e0::/48"]
        );
        assert_eq!(node.hostinfo.os, "linux");
        assert_eq!(node.hostinfo.os_version, "6.8");
    }

    #[test]
    fn record_to_map_node_keeps_unqualified_name_without_dns_domain() {
        let record = MachineRecord::new_at(
            chrono::Utc::now(),
            "aa".repeat(32),
            "bb".repeat(32),
            "alice".into(),
            "router-a".into(),
            Ipv4Addr::new(100, 64, 0, 8),
            false,
        );

        let node = record_to_map_node(&record, "");

        assert_eq!(node.name, "router-a");
    }

    #[test]
    fn record_to_map_node_uses_decimal_node_id_as_stable_id() {
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            "aa".repeat(32),
            "bb".repeat(32),
            "alice".into(),
            "router-a".into(),
            Ipv4Addr::new(100, 64, 0, 8),
            false,
        );
        record.node_id = Some(42);

        let node = record_to_map_node(&record, "octra.test");

        assert_eq!(node.id, 42);
        assert_eq!(node.stable_id, "42");
    }

    #[test]
    fn record_to_map_node_emits_ipv4_and_ipv6_prefixes() {
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            "ab".repeat(32),
            "cd".repeat(32),
            "alice".into(),
            "dual-a".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            false,
        );
        record.ipv6 = Some("fd7a:115c:a1e0::9".parse().unwrap());
        record.approved_routes = vec!["10.10.0.0/24".into()];

        let node = record_to_map_node(&record, "octra.test");

        assert_eq!(
            node.addresses,
            vec!["100.64.0.9/32", "fd7a:115c:a1e0::9/128"]
        );
        assert_eq!(
            node.allowed_ips,
            vec!["100.64.0.9/32", "fd7a:115c:a1e0::9/128", "10.10.0.0/24"]
        );
    }

    #[test]
    fn record_to_map_node_emits_ipv6_only_prefixes() {
        let record = MachineRecord::new_at_with_addresses(
            chrono::Utc::now(),
            "af".repeat(32),
            "cd".repeat(32),
            "alice".into(),
            "v6-only".into(),
            None,
            Some("fd7a:115c:a1e0::66".parse().unwrap()),
            false,
        );

        let node = record_to_map_node(&record, "octra.test");

        assert_eq!(node.addresses, vec!["fd7a:115c:a1e0::66/128"]);
        assert_eq!(node.allowed_ips, vec!["fd7a:115c:a1e0::66/128"]);
    }

    #[tokio::test]
    async fn oidc_router_register_starts_auth_code_flow() {
        let (state, _redeemer, _dir) = fixture();
        let oidc = oidc_runtime();
        let app = router_with_oidc(state, oidc.clone());
        let registration_id = "a".repeat(24);
        let auth_id = format!("{AUTH_ID_PREFIX}{registration_id}");

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/register/{auth_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(location.starts_with("https://issuer.example/oauth2/auth?"));
        assert!(location.contains("client_id=headscale-rs"));
        assert!(
            location.contains("redirect_uri=https%3A%2F%2Fheadscale.example%2Foidc%2Fcallback")
        );
        assert!(location.contains("code_challenge_method=S256"));
        assert!(location.contains("domain_hint=example.com"));
        let state = location
            .split_once("state=")
            .and_then(|(_, rest)| rest.split('&').next())
            .expect("auth URL includes state");
        let cached = oidc.registration(state).unwrap();
        assert_eq!(cached.registration_id, registration_id);
        assert!(cached.registration);
        assert_eq!(
            resp.headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn oidc_router_auth_starts_auth_code_flow() {
        let (state, _redeemer, _dir) = fixture();
        let oidc = oidc_runtime();
        let app = router_with_oidc(state, oidc.clone());
        let raw_auth_id = "s".repeat(24);
        let auth_id = format!("{AUTH_ID_PREFIX}{raw_auth_id}");

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/auth/{auth_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(location.starts_with("https://issuer.example/oauth2/auth?"));
        let state = location
            .split_once("state=")
            .and_then(|(_, rest)| rest.split('&').next())
            .expect("auth URL includes state");
        let cached = oidc.registration(state).unwrap();
        assert_eq!(cached.registration_id, raw_auth_id);
        assert!(!cached.registration);
    }

    #[test]
    fn record_to_map_node_uses_tagged_devices_user_for_tagged_records() {
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            "cc".repeat(32),
            "dd".repeat(32),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            false,
        );
        record.forced_tags = vec!["tag:server".into()];

        let node = record_to_map_node(&record, "octra.test");

        assert_eq!(
            node.user,
            crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID
        );
    }

    #[test]
    fn followup_registration_id_parses_relative_and_absolute_urls() {
        let id = "3oYCOZYA2zZmGB4PQ7aHBaMi";
        let auth_id = format!("{AUTH_ID_PREFIX}{id}");
        assert_eq!(
            registration_id_from_followup(&format!("/register/{auth_id}")).unwrap(),
            id
        );
        assert_eq!(
            registration_id_from_followup(&format!("https://headscale.example/register/{auth_id}"))
                .unwrap(),
            id
        );
        assert!(registration_id_from_followup(&format!("/register/{id}")).is_err());
        assert!(registration_id_from_followup("/register/short").is_err());
        assert!(registration_id_from_followup("https://headscale.example/oidc/callback").is_err());
    }

    #[tokio::test]
    async fn register_requires_noise_machine_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-no-noise-machine-key";
        redeemer.insert(authkey, "alice");
        let app = machine_router(state.clone());
        let node_key_hex = "a0".repeat(32);
        let body = req_body(&node_key_hex, authkey);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(state.machines.get(&node_key_hex).is_none());
    }

    #[tokio::test]
    async fn register_rejects_unsupported_capability_version() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-unsupported-capver";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "a2".repeat(32);
        let mut body = req_body(&node_key_hex, authkey);
        body["Version"] = serde_json::json!(112);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"unsupported client version:  (112)\n");
        assert!(state.machines.get(&node_key_hex).is_none());
        assert!(redeemer.contains(authkey));
    }

    #[tokio::test]
    async fn register_malformed_json_without_version_matches_go_unsupported_response() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .body(axum::body::Body::from(b"{".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"unsupported client version:  (0)\n");
    }

    #[tokio::test]
    async fn register_supported_bad_json_shape_returns_register_response_error() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .body(axum::body::Body::from(
                        br#"{"Version":113,"NodeKey":1}"#.to_vec(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!rr.error.is_empty());
        assert!(!rr.machine_authorized);
    }

    #[tokio::test]
    async fn happy_path_redeems_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-alice-test-key";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "aa".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let raw_str = String::from_utf8_lossy(&raw);
        // Pin upstream JSON tag name: `AuthURL` (all-caps URL), not
        // PascalCase `AuthUrl`. Go's encoding/json is case-insensitive
        // on decode so either survives the client side; the wire-format
        // test pins the encoded shape so future regressions don't slip
        // through.
        assert!(
            raw_str.contains("\"AuthURL\""),
            "expected AuthURL field name; got: {raw_str}"
        );
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert_eq!(rr.login.login_name, "alice");
        // Mock redeemer is single-use — second redeem fails.
        assert!(!redeemer.contains(authkey));
        // Machine registry remembers the registration.
        assert_eq!(state.machines.len(), 1);
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.hostname, "peer-a");
        assert_eq!(rec.os, "linux");
        assert_eq!(rec.os_version, "6.6");
        // Allocated IP is in CGNAT.
        assert!(rec.ipv4.expect("IPv4 allocated").octets()[0] == 100);
    }

    #[tokio::test]
    async fn authkey_register_accepts_ipv6_only_allocator() {
        let (mut state, redeemer, _dir) = fixture();
        state.ip_allocator = Arc::new(Ipv6OnlyAllocator);
        let authkey = "hskey-auth-v6-only";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "1f".repeat(32);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body(&node_key_hex, authkey)).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.ipv4, None);
        assert_eq!(
            rec.ipv6.map(|ip| ip.to_string()).as_deref(),
            Some("fd7a:115c:a1e0::66")
        );
        let node = record_to_map_node(&rec, "octra.test");
        assert_eq!(node.addresses, vec!["fd7a:115c:a1e0::66/128"]);
    }

    #[tokio::test]
    async fn authkey_register_projects_persistent_store_result() {
        let (mut state, redeemer, _dir) = fixture();
        let store = Arc::new(RecordingRegistrationStore::default());
        state.registration_store = Some(store.clone());
        let authkey = "hskey-auth-persistent-store";
        redeemer.insert_full(authkey, RedeemOk::for_user("alice").auth_key_id(42));
        let app = router(state.clone());
        let node_key_hex = "11".repeat(32);
        let body = req_body(&node_key_hex, authkey);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);

        let calls = store.calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, Some(42));
        assert_eq!(calls[0].0.hostname, "peer-a");
        drop(calls);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.hostname, "persisted-peer");
        assert_eq!(rec.ipv4, Some(Ipv4Addr::new(100, 64, 9, 9)));
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn authkey_register_persistent_store_writes_go_node_fk() {
        use crate::admin::machines::PersistentMachineAdmin;
        use crate::admin::preauth::{PreauthAdmin, PreauthMintRequest};
        use crate::admin::preauth_persistent::PersistentPreauthAdmin;
        use crate::admin::users::{PersistentUserAdmin, UserAdmin};

        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let preauth = Arc::new(
            PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone()),
        );
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users));
        let key = preauth
            .mint(PreauthMintRequest {
                user: "alice".into(),
                ttl_secs: 3600,
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
            })
            .await
            .unwrap();

        let (mut state, _redeemer, _dir) = fixture();
        state.preauth = preauth;
        state.registration_store = Some(machines);
        let app = router(state.clone());
        let node_key_hex = "16".repeat(32);
        let mut body = req_body(&node_key_hex, &key.key);
        body["Hostinfo"]["IPNVersion"] = serde_json::json!("1.82.0-register");
        body["Hostinfo"]["Distro"] = serde_json::json!("fedora");
        body["Hostinfo"]["NetInfo"] = serde_json::json!({
            "PreferredDERP": 44,
            "WorkingUDP": true,
            "LinkType": "wifi",
            "DERPLatency": {
                "44-v4": 0.034
            }
        });

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{node_key_hex}"),
        )
        .await
        .unwrap();
        assert_eq!(raw.auth_key_id, Some(key.id as i64));
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
        let host_info = raw.host_info_value();
        assert_eq!(host_info["OS"], "linux");
        assert_eq!(host_info["OSVersion"], "6.6");
        assert_eq!(host_info["IPNVersion"], "1.82.0-register");
        assert_eq!(host_info["Distro"], "fedora");
        assert_eq!(host_info["NetInfo"]["PreferredDERP"], 44);
        assert_eq!(host_info["NetInfo"]["WorkingUDP"], true);
        assert_eq!(host_info["NetInfo"]["LinkType"], "wifi");
        assert_eq!(host_info["NetInfo"]["DERPLatency"]["44-v4"], 0.034);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.os, "linux");
        assert_eq!(rec.os_version, "6.6");
        assert_eq!(rec.host_info.ipn_version, "1.82.0-register");
        assert_eq!(rec.host_info.distro, "fedora");
        let net_info = rec.host_info.net_info.expect("registry NetInfo");
        assert_eq!(net_info.preferred_derp, 44);
        assert_eq!(net_info.working_udp, Some(true));
        assert_eq!(net_info.link_type, "wifi");
        assert_eq!(net_info.derp_latency.get("44-v4"), Some(&0.034));
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn authkey_register_persistent_store_rekeys_existing_machine() {
        use crate::admin::machines::PersistentMachineAdmin;
        use crate::admin::preauth::{PreauthAdmin, PreauthMintRequest};
        use crate::admin::preauth_persistent::PersistentPreauthAdmin;
        use crate::admin::users::{PersistentUserAdmin, UserAdmin};

        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let preauth = Arc::new(
            PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone()),
        );
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users));
        let mint = || PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 3600,
            reusable: false,
            ephemeral: false,
            tags: Vec::new(),
        };
        let first_key = preauth.mint(mint()).await.unwrap();
        let second_key = preauth.mint(mint()).await.unwrap();

        let (mut state, _redeemer, _dir) = fixture();
        state.preauth = preauth;
        state.registration_store = Some(machines);
        let app = router(state.clone());
        let first_node_key = "19".repeat(32);
        let second_node_key = "1a".repeat(32);
        let machine_key_hex = "91".repeat(32);

        let mut first = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&first_node_key, &first_key.key)).unwrap(),
            ))
            .unwrap();
        first
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(first).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let first_ip = state.machines.get(&first_node_key).unwrap().ipv4;

        let mut second_body = req_body(&second_node_key, &second_key.key);
        second_body["Hostinfo"]["Hostname"] = serde_json::json!("peer-rotated");
        let mut second = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{second_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&second_body).unwrap(),
            ))
            .unwrap();
        second
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.oneshot(second).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(state.machines.len(), 1);
        assert!(state.machines.get(&first_node_key).is_none());
        let rotated = state.machines.get(&second_node_key).unwrap();
        assert_eq!(rotated.machine_key_hex, machine_key_hex);
        assert_eq!(rotated.hostname, "peer-rotated");
        assert_eq!(rotated.ipv4, first_ip);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{second_node_key}"),
        )
        .await
        .unwrap();
        assert_eq!(raw.auth_key_id, Some(second_key.id as i64));
        assert_eq!(raw.ipv4, first_ip.map(|ip| ip.to_string()));
    }

    #[tokio::test]
    async fn authkey_tagged_preauth_disables_requested_expiry() {
        let (mut state, redeemer, _dir) = fixture();
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let authkey = "hskey-auth-tagged-expiry";
        redeemer.insert_full(
            authkey,
            RedeemOk::for_user("alice").tags(vec!["tag:server".into(), "tag:prod".into()]),
        );
        let app = router(state.clone());
        let node_key_hex = "12".repeat(32);
        let requested_expiry = chrono::Utc::now() + chrono::Duration::hours(24);
        let mut body = req_body(&node_key_hex, authkey);
        body["Expiry"] = serde_json::json!(requested_expiry);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            rr.user.id,
            crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID
        );
        assert_eq!(rr.user.display_name, "Tagged Devices");
        assert_eq!(rr.login.provider, "");
        assert_eq!(rr.login.login_name, "tagged-devices");
        assert_eq!(rr.login.display_name, "Tagged Devices");

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:server", "tag:prod"]);
        assert!(
            rec.expiry.is_none(),
            "tagged preauth registrations disable node-key expiry"
        );
    }

    #[tokio::test]
    async fn authkey_preauth_rejects_client_requested_tags() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-request-tags";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "18".repeat(32);
        let mut body = req_body(&node_key_hex, authkey);
        body["Hostinfo"]["RequestTags"] = serde_json::json!(["tag:server", "tag:server", "tag:db"]);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            ev["error"],
            "requested tags [tag:db tag:server] are invalid or not permitted"
        );
        assert!(state.machines.get(&node_key_hex).is_none());
    }

    #[tokio::test]
    async fn authkey_untagged_preauth_preserves_requested_expiry() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-untagged-expiry";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "13".repeat(32);
        let requested_expiry = chrono::Utc::now() + chrono::Duration::hours(24);
        let mut body = req_body(&node_key_hex, authkey);
        body["Expiry"] = serde_json::json!(requested_expiry);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert!(rec.forced_tags.is_empty());
        assert_eq!(rec.expiry, Some(requested_expiry));
    }

    #[tokio::test]
    async fn authkey_untagged_applies_node_expiry_when_client_expiry_absent() {
        let (mut state, redeemer, _dir) = fixture();
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let authkey = "hskey-auth-node-expiry-default";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "16".repeat(32);
        let before = chrono::Utc::now();
        let body = req_body(&node_key_hex, authkey);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rec = state.machines.get(&node_key_hex).unwrap();
        let expiry = rec.expiry.expect("node.expiry default applied");
        assert!(expiry >= before + chrono::Duration::seconds(3600));
        assert!(expiry <= chrono::Utc::now() + chrono::Duration::seconds(3600));
    }

    #[tokio::test]
    async fn authkey_untagged_preauth_ignores_go_zero_expiry() {
        let (mut state, redeemer, _dir) = fixture();
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(7200)));
        let authkey = "hskey-auth-zero-expiry";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "15".repeat(32);
        let mut body = req_body(&node_key_hex, authkey);
        body["Expiry"] = serde_json::json!("0001-01-01T00:00:00Z");

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!rr.node_key_expired);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert!(rec.forced_tags.is_empty());
        let expiry = rec.expiry.expect("Go zero time falls back to node.expiry");
        assert!(expiry > chrono::Utc::now() + chrono::Duration::seconds(7100));
    }

    #[tokio::test]
    async fn authkey_node_expiry_zero_yields_no_default_expiry() {
        let (mut state, redeemer, _dir) = fixture();
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::ZERO));
        let authkey = "hskey-auth-node-expiry-zero";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "1e".repeat(32);
        let body = req_body(&node_key_hex, authkey);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.machines.get(&node_key_hex).unwrap().expiry.is_none());
    }

    #[tokio::test]
    async fn authkey_tagged_reauth_preserves_disabled_expiry() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-tagged-reauth-first";
        let second_authkey = "hskey-auth-tagged-reauth-second";
        redeemer.insert_full(
            first_authkey,
            RedeemOk::for_user("alice").tags(vec!["tag:server".into()]),
        );
        redeemer.insert_full(
            second_authkey,
            RedeemOk::for_user("alice").tags(vec!["tag:server".into()]),
        );
        let app = router(state.clone());
        let node_key_hex = "14".repeat(32);
        let first_expiry = chrono::Utc::now() + chrono::Duration::hours(24);
        let mut first_body = req_body(&node_key_hex, first_authkey);
        first_body["Expiry"] = serde_json::json!(first_expiry);

        let first = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&first_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert!(state.machines.get(&node_key_hex).unwrap().expiry.is_none());

        let second_expiry = chrono::Utc::now() + chrono::Duration::hours(48);
        let mut second_body = req_body(&node_key_hex, second_authkey);
        second_body["Expiry"] = serde_json::json!(second_expiry);
        let second = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&second_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:server"]);
        assert!(
            rec.expiry.is_none(),
            "tagged reauth keeps node-key expiry disabled"
        );
    }

    #[tokio::test]
    async fn tagged_existing_node_zero_expiry_restart_preserves_nil_expiry() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-tagged-zero-restart";
        redeemer.insert_full(
            authkey,
            RedeemOk::for_user("alice").tags(vec!["tag:agent".into()]),
        );
        let app = router(state.clone());
        let node_key_hex = "1f".repeat(32);
        let body = req_body(&node_key_hex, authkey);

        let first = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:agent"]);
        assert!(rec.expiry.is_none());

        let restart_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": "0001-01-01T00:00:00Z",
        });
        let restart = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&restart_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restart.status(), StatusCode::OK);
        let raw = to_bytes(restart.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);
        assert_eq!(
            rr.user.id,
            crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID
        );
        assert_eq!(rr.login.login_name, "tagged-devices");

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.forced_tags, vec!["tag:agent"]);
        assert!(!rec.is_expired_at(chrono::Utc::now()));
        assert!(
            rec.expiry.is_none(),
            "tagged node restart must keep nil expiry, not a Go zero timestamp"
        );
    }

    #[tokio::test]
    async fn authkey_register_persists_noise_machine_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-machine-key";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "35".repeat(32);
        let machine_key_hex = "44".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.machine_key_hex, machine_key_hex);
        let node = record_to_map_node(&rec, "example.test");
        let expected_machine = format!("mkey:{machine_key_hex}");
        assert_eq!(node.machine.as_deref(), Some(expected_machine.as_str()));
    }

    #[tokio::test]
    async fn authkey_register_same_machine_user_rotates_node_key_in_place() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-rotation-first";
        let second_authkey = "hskey-auth-rotation-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert(second_authkey, "alice");
        let app = router(state.clone());
        let first_node_key = "38".repeat(32);
        let second_node_key = "39".repeat(32);
        let machine_key_hex = "88".repeat(32);

        let mut body = req_body(&first_node_key, first_authkey);
        body["Hostinfo"]["RoutableIPs"] = serde_json::json!(["10.40.0.0/24"]);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.machines.len(), 1);

        let mut first = state.machines.get(&first_node_key).unwrap();
        let first_ipv4 = first.ipv4;
        let first_created_at = first.created_at;
        first.node_id = Some(8800);
        first.user_id = Some(42);
        first.disco_key = Some("discokey:old".into());
        first.endpoints = vec!["198.51.100.10:41641".into()];
        first.approved_routes = vec!["10.40.0.0/24".into(), "10.41.0.0/24".into()];
        state.machines.upsert(first_node_key.clone(), first);

        let mut body = req_body(&second_node_key, second_authkey);
        body["Hostinfo"]["Hostname"] = serde_json::json!("peer-rotated");
        body["Hostinfo"]["RoutableIPs"] = serde_json::json!(["10.40.0.0/24", "10.42.0.0/24"]);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{second_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);

        assert_eq!(state.machines.len(), 1);
        assert!(state.machines.get(&first_node_key).is_none());
        let rotated = state.machines.get(&second_node_key).unwrap();
        assert_eq!(rotated.node_key_hex, second_node_key);
        assert_eq!(rotated.machine_key_hex, machine_key_hex);
        assert_eq!(rotated.user, "alice");
        assert_eq!(rotated.node_id, Some(8800));
        assert_eq!(rotated.user_id, Some(42));
        assert_eq!(rotated.hostname, "peer-rotated");
        assert_eq!(rotated.ipv4, first_ipv4);
        assert_eq!(rotated.created_at, first_created_at);
        assert_eq!(rotated.disco_key.as_deref(), Some("discokey:old"));
        assert_eq!(rotated.endpoints, vec!["198.51.100.10:41641"]);
        assert_eq!(
            rotated.available_routes,
            vec!["10.40.0.0/24", "10.42.0.0/24"]
        );
        assert_eq!(
            rotated.approved_routes,
            vec!["10.40.0.0/24", "10.41.0.0/24"]
        );
    }

    #[tokio::test]
    async fn authkey_register_same_machine_different_user_creates_new_node() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-different-user-first";
        let second_authkey = "hskey-auth-different-user-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert(second_authkey, "bob");
        let app = router(state.clone());
        let first_node_key = "6a".repeat(32);
        let second_node_key = "6b".repeat(32);
        let machine_key_hex = "b6".repeat(32);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&first_node_key, first_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.machines.len(), 1);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{second_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&second_node_key, second_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);
        assert_eq!(rr.login.login_name, "bob");

        assert_eq!(state.machines.len(), 2);
        let first = state.machines.get(&first_node_key).unwrap();
        assert_eq!(first.user, "alice");
        let second = state.machines.get(&second_node_key).unwrap();
        assert_eq!(second.user, "bob");
        assert_eq!(second.machine_key_hex, first.machine_key_hex);
        assert_ne!(second.ipv4, first.ipv4);
        assert!(!redeemer.contains(second_authkey));
    }

    #[tokio::test]
    async fn authkey_logout_relogin_different_user_creates_new_node() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-logout-different-user-first";
        let second_authkey = "hskey-auth-logout-different-user-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert(second_authkey, "bob");
        let app = router(state.clone());
        let first_node_key = "6c".repeat(32);
        let second_node_key = "6d".repeat(32);
        let machine_key_hex = "b8".repeat(32);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&first_node_key, first_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let logout_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{first_node_key}"),
            "Expiry": chrono::Utc::now() - chrono::Duration::minutes(1),
        });
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&logout_body).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.node_key_expired);
        assert!(
            state
                .machines
                .get(&first_node_key)
                .unwrap()
                .is_expired_at(chrono::Utc::now())
        );

        let mut body = req_body(&second_node_key, second_authkey);
        body["Hostinfo"]["Hostname"] = serde_json::json!("peer-bob");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{second_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);
        assert_eq!(rr.login.login_name, "bob");

        assert_eq!(state.machines.len(), 2);
        let original = state.machines.get(&first_node_key).unwrap();
        assert_eq!(original.user, "alice");
        assert!(original.is_expired_at(chrono::Utc::now()));
        let relogin = state.machines.get(&second_node_key).unwrap();
        assert_eq!(relogin.user, "bob");
        assert_eq!(relogin.hostname, "peer-bob");
        assert!(!relogin.is_expired_at(chrono::Utc::now()));
    }

    #[tokio::test]
    async fn authkey_register_same_machine_tagged_key_can_create_tag_owned_node() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-tagged-different-user-first";
        let tagged_authkey = "hskey-auth-tagged-different-user-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert_full(
            tagged_authkey,
            RedeemOk::for_user("bob").tags(vec!["tag:server".into()]),
        );
        let app = router(state.clone());
        let first_node_key = "7a".repeat(32);
        let tagged_node_key = "7b".repeat(32);
        let machine_key_hex = "b7".repeat(32);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&first_node_key, first_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{tagged_node_key}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&tagged_node_key, tagged_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);

        assert_eq!(state.machines.len(), 2);
        let tagged = state.machines.get(&tagged_node_key).unwrap();
        assert_eq!(tagged.user, "bob");
        assert_eq!(tagged.forced_tags, vec!["tag:server"]);
        assert!(!redeemer.contains(tagged_authkey));
    }

    #[tokio::test]
    async fn authkey_reauth_persists_unadvertised_approved_routes() {
        let (mut state, redeemer, _dir) = fixture();
        let store = Arc::new(RecordingRegistrationStore::default());
        state.registration_store = Some(store.clone());
        let first_authkey = "hskey-auth-route-persist-first";
        let second_authkey = "hskey-auth-route-persist-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert(second_authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "5a".repeat(32);
        let machine_key_hex = "a5".repeat(32);

        let mut body = req_body(&node_key_hex, first_authkey);
        body["Hostinfo"]["RoutableIPs"] = serde_json::json!(["10.40.0.0/24", "10.41.0.0/24"]);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut approved = state.machines.get(&node_key_hex).unwrap();
        approved.approved_routes = vec!["10.40.0.0/24".into(), "10.41.0.0/24".into()];
        state.machines.upsert(node_key_hex.clone(), approved);

        let mut body = req_body(&node_key_hex, second_authkey);
        body["Hostinfo"]["RoutableIPs"] = serde_json::json!(["10.40.0.0/24"]);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let calls = store.calls.lock();
        assert_eq!(calls.len(), 2);
        let reauth_record = &calls[1].0;
        assert_eq!(reauth_record.available_routes, vec!["10.40.0.0/24"]);
        assert_eq!(
            reauth_record.approved_routes,
            vec!["10.40.0.0/24", "10.41.0.0/24"]
        );
        drop(calls);

        let reauthed = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(reauthed.available_routes, vec!["10.40.0.0/24"]);
        assert_eq!(
            reauthed.approved_routes,
            vec!["10.40.0.0/24", "10.41.0.0/24"]
        );
    }

    #[tokio::test]
    async fn authkey_reregister_preserves_admin_renamed_given_name() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-admin-name-first";
        let second_authkey = "hskey-auth-admin-name-second";
        redeemer.insert(first_authkey, "alice");
        redeemer.insert(second_authkey, "alice");
        let app = router(state.clone());
        let first_node_key = "3c".repeat(32);
        let second_node_key = "3d".repeat(32);
        let machine_key_hex = "8c".repeat(32);

        let body = req_body(&first_node_key, first_authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{first_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.machines.rename(&first_node_key, "admin-name".into()));

        let mut body = req_body(&second_node_key, second_authkey);
        body["Hostinfo"]["Hostname"] = serde_json::json!("client-new-host");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{second_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert!(state.machines.get(&first_node_key).is_none());
        let rotated = state.machines.get(&second_node_key).unwrap();
        assert_eq!(rotated.hostname, "admin-name");
        assert_eq!(rotated.host_info_for_node().hostname, "client-new-host");
    }

    #[tokio::test]
    async fn authkey_machine_rekey_rejects_occupied_node_key() {
        let (state, redeemer, _dir) = fixture();
        redeemer.insert("hskey-auth-alice-first", "alice");
        redeemer.insert("hskey-auth-bob", "bob");
        redeemer.insert("hskey-auth-alice-rotate", "alice");
        let app = router(state.clone());
        let alice_node_key = "3a".repeat(32);
        let bob_node_key = "3b".repeat(32);
        let alice_machine_key = "8a".repeat(32);
        let bob_machine_key = "8b".repeat(32);

        for (node_key, machine_key, authkey) in [
            (
                &alice_node_key,
                &alice_machine_key,
                "hskey-auth-alice-first",
            ),
            (&bob_node_key, &bob_machine_key, "hskey-auth-bob"),
        ] {
            let body = req_body(node_key, authkey);
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{node_key}/register"))
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
            req.extensions_mut()
                .insert(NoisePeerMachineKey(machine_key.clone()));
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let body = req_body(&bob_node_key, "hskey-auth-alice-rotate");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{bob_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(alice_machine_key.clone()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(ev["error"], "node key already exists");
        assert_eq!(state.machines.len(), 2);
        assert_eq!(
            state.machines.get(&bob_node_key).unwrap().machine_key_hex,
            bob_machine_key
        );
        assert!(state.machines.get(&alice_node_key).is_some());
    }

    #[tokio::test]
    async fn authkey_existing_node_can_reregister_with_used_key() {
        let (mut state, redeemer, _dir) = fixture();
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let authkey = "hskey-auth-used-reregister";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "3c".repeat(32);
        let machine_key_hex = "8c".repeat(32);

        let body = req_body(&node_key_hex, authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!redeemer.contains(authkey));
        assert_eq!(state.machines.len(), 1);
        let first_expiry = state
            .machines
            .get(&node_key_hex)
            .unwrap()
            .expiry
            .expect("first registration applied default expiry");

        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(7200)));
        let app = router(state.clone());

        let mut body = req_body(&node_key_hex, authkey);
        body["Hostinfo"]["Hostname"] = serde_json::json!("peer-restarted");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);
        assert_eq!(state.machines.len(), 1);
        assert_eq!(
            state.machines.get(&node_key_hex).unwrap().hostname,
            "peer-restarted"
        );
        let second_expiry = state
            .machines
            .get(&node_key_hex)
            .unwrap()
            .expiry
            .expect("reauth refreshed default expiry");
        assert!(second_expiry > first_expiry + chrono::Duration::minutes(50));

        let attacker_node_key = "3d".repeat(32);
        let body = req_body(&attacker_node_key, authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{attacker_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey("8d".repeat(32)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rr.error, "preauth key already used");
        assert_eq!(state.machines.len(), 1);
    }

    #[tokio::test]
    async fn authkey_used_key_reregister_requires_original_auth_key_id_when_known() {
        let (state, redeemer, _dir) = fixture();
        let first_authkey = "hskey-auth-used-original-id";
        let second_authkey = "hskey-auth-used-other-id";
        redeemer.insert_full(first_authkey, RedeemOk::for_user("alice").auth_key_id(101));
        redeemer.insert_full(second_authkey, RedeemOk::for_user("alice").auth_key_id(202));
        let app = router(state.clone());
        let node_key_hex = "5b".repeat(32);
        let machine_key_hex = "b5".repeat(32);

        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&req_body(&node_key_hex, first_authkey)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let registered = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(registered.auth_key_id, Some(101));

        let consumed = redeemer.redeem(second_authkey).await.unwrap();
        assert_eq!(consumed.auth_key_id, Some(202));

        let mut wrong_key_body = req_body(&node_key_hex, second_authkey);
        wrong_key_body["Hostinfo"]["Hostname"] = serde_json::json!("wrong-used-key");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&wrong_key_body).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rr.error, "preauth key already used");
        let unchanged = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(unchanged.auth_key_id, Some(101));
        assert_ne!(unchanged.hostname, "wrong-used-key");

        let mut original_key_body = req_body(&node_key_hex, first_authkey);
        original_key_body["Hostinfo"]["Hostname"] = serde_json::json!("original-used-key");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&original_key_body).unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        let reauthed = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(reauthed.auth_key_id, Some(101));
        assert_eq!(reauthed.hostname, "original-used-key");
    }

    #[tokio::test]
    async fn authkey_existing_node_can_reregister_with_expired_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-expiring-reregister";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "3e".repeat(32);
        let machine_key_hex = "8e".repeat(32);

        let body = req_body(&node_key_hex, authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(redeemer.expire(authkey));

        let mut body = req_body(&node_key_hex, authkey);
        body["Hostinfo"]["Hostname"] = serde_json::json!("peer-expired-restart");
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert_eq!(
            state.machines.get(&node_key_hex).unwrap().hostname,
            "peer-expired-restart"
        );

        let expired_new_key = "hskey-auth-expired-new-node";
        redeemer.insert_expired(expired_new_key, RedeemOk::for_user("alice"));
        let new_node_key = "3f".repeat(32);
        let body = req_body(&new_node_key, expired_new_key);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{new_node_key}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey("8f".repeat(32)));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rr.error, "preauth key expired");
    }

    #[tokio::test]
    async fn interactive_register_cache_persists_noise_machine_key() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        let app = router(state.clone());
        let node_key_hex = "36".repeat(32);
        let machine_key_hex = "55".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending-machine-key" },
        });
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let auth_id = rr
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .unwrap();
        let registration_id = auth_id
            .strip_prefix(AUTH_ID_PREFIX)
            .expect("AuthURL uses current-upstream auth ID prefix");
        let pending = state.registration_cache.get(registration_id).unwrap();
        assert_eq!(pending.machine_key_hex, machine_key_hex);
    }

    #[tokio::test]
    async fn existing_node_no_auth_rejects_mismatched_noise_machine_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-machine-key-mismatch";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "37".repeat(32);
        let machine_key_hex = "66".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state.machines.get(&node_key_hex).unwrap().machine_key_hex,
            machine_key_hex
        );

        let restart_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
        });
        let mut restart = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(
                serde_json::to_vec(&restart_body).unwrap(),
            ))
            .unwrap();
        restart
            .extensions_mut()
            .insert(NoisePeerMachineKey("77".repeat(32)));
        let resp = app.oneshot(restart).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rr.error, "node exists with a different machine key");
    }

    #[tokio::test]
    async fn existing_node_no_auth_restart_returns_current_registration() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-restart-alice";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "31".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let restart_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
        });
        let restart_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&restart_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(restart_resp.status(), StatusCode::OK);
        let raw = to_bytes(restart_resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert!(!rr.node_key_expired);
        assert_eq!(rr.login.login_name, "alice");
        assert!(rr.auth_url.is_empty());
        assert_eq!(state.machines.len(), 1);
        assert!(state.registration_cache.is_empty());
    }

    #[tokio::test]
    async fn existing_node_legacy_oauth2_auth_starts_interactive_registration_like_go() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-legacy-oauth2-existing";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "3a".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let oauth2_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Auth": {
                "Oauth2Token": {
                    "access_token": "legacy-access-token",
                    "token_type": "Bearer"
                }
            },
            "Hostinfo": { "Hostname": "legacy-oauth2-existing" },
        });
        let oauth2_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&oauth2_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(oauth2_resp.status(), StatusCode::OK);
        let raw = to_bytes(oauth2_resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!rr.machine_authorized);
        assert!(rr.login.login_name.is_empty());
        assert!(rr.auth_url.starts_with("/register/hskey-authreq-"));
        assert_eq!(state.machines.len(), 1);
        assert_eq!(state.registration_cache.len(), 1);
    }

    #[tokio::test]
    async fn existing_node_no_auth_future_expiry_is_rejected() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-future-expiry";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "32".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": future,
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(ev["error"], "extending key is not allowed");
        assert!(state.machines.get(&node_key_hex).unwrap().expiry.is_none());
        assert!(state.registration_cache.is_empty());
    }

    #[tokio::test]
    async fn existing_node_no_auth_past_expiry_logs_out_persistent_node() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-logout-persistent";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "33".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let past = chrono::Utc::now() - chrono::Duration::minutes(1);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": past,
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.node_key_expired);
        assert!(rr.machine_authorized);
        assert_eq!(rr.login.login_name, "alice");
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert!(rec.is_expired_at(chrono::Utc::now()));
    }

    #[tokio::test]
    async fn already_expired_node_past_expiry_forces_reauth_without_reauthorizing() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-expired-logout-persistent";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "39".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let past = chrono::Utc::now() - chrono::Duration::minutes(10);
        assert!(state.machines.set_expiry(&node_key_hex, Some(past)));
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": chrono::Utc::now() - chrono::Duration::minutes(1),
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.node_key_expired);
        assert!(!rr.machine_authorized);
        assert!(rr.auth_url.is_empty());
        assert!(state.machines.get(&node_key_hex).is_some());
    }

    #[tokio::test]
    async fn existing_node_no_auth_past_expiry_deletes_ephemeral_node() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-logout-ephemeral";
        redeemer.insert_full(authkey, RedeemOk::for_user("alice").ephemeral(true));
        let app = router(state.clone());
        let node_key_hex = "34".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(state.machines.get(&node_key_hex).unwrap().ephemeral);

        let past = chrono::Utc::now() - chrono::Duration::minutes(1);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": past,
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.node_key_expired);
        assert!(!rr.machine_authorized);
        assert!(state.machines.get(&node_key_hex).is_none());
    }

    #[tokio::test]
    async fn register_auto_approves_policy_routes() {
        let (state, redeemer, _dir) = fixture();
        let policy = r#"{
            "autoApprovers": {
                "routes": {"10.30.0.0/16": ["alice@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let authkey = "hskey-auth-alice-routes";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "ab".repeat(32);
        let mut body = req_body(&node_key_hex, authkey);
        body["Hostinfo"]["RoutableIPs"] = serde_json::json!(["10.30.1.0/24", "10.99.0.0/24"]);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.available_routes, vec!["10.30.1.0/24", "10.99.0.0/24"]);
        assert_eq!(rec.approved_routes, vec!["10.30.1.0/24"]);
    }

    #[tokio::test]
    async fn rejects_unknown_authkey() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let node_key_hex = "bb".repeat(32);
        let body = req_body(&node_key_hex, "hskey-auth-deadbeef");
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.error.contains("not recognised"));
    }

    #[tokio::test]
    async fn missing_authkey_starts_web_registration_flow() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        let app = router(state.clone());
        let node_key_hex = "cc".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending-peer", "RoutableIPs": ["10.44.0.0/24"] },
            "Expiry": "0001-01-01T00:00:00Z",
            "Ephemeral": true,
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!rr.machine_authorized);
        let auth_id = rr
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .expect("configured web registration AuthURL");
        let registration_id = auth_id
            .strip_prefix(AUTH_ID_PREFIX)
            .expect("AuthURL uses current-upstream auth ID prefix");
        assert_eq!(auth_id.len(), AUTH_ID_LENGTH);
        assert_eq!(registration_id.len(), 24);
        assert!(state.machines.get(&node_key_hex).is_none());
        let pending = state
            .registration_cache
            .get(registration_id)
            .expect("pending registration cached");
        assert_eq!(pending.node_key_hex, node_key_hex);
        assert_eq!(pending.hostname, "pending-peer");
        assert_eq!(pending.available_routes, vec!["10.44.0.0/24"]);
        assert!(pending.expiry.is_none());
        assert!(pending.ephemeral);
    }

    #[tokio::test]
    async fn rejected_followup_restarts_web_registration_like_headscale_go() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        let app = router(state.clone());
        let node_key_hex = "ce".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "rejected-followup" },
        });

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let first: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let first_auth_id = first
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .unwrap();
        let first_registration_id = first_auth_id.strip_prefix(AUTH_ID_PREFIX).unwrap();
        assert!(
            state
                .registration_cache
                .reject(first_registration_id, "auth request rejected")
        );

        let followup_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Followup": first.auth_url,
            "Hostinfo": { "Hostname": "rejected-followup" },
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&followup_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let refreshed: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!refreshed.machine_authorized);
        assert!(refreshed.error.is_empty());
        let refreshed_auth_id = refreshed
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .unwrap();
        assert_ne!(refreshed_auth_id, first_auth_id);
        let refreshed_registration_id = refreshed_auth_id.strip_prefix(AUTH_ID_PREFIX).unwrap();
        assert!(
            state
                .registration_cache
                .get(refreshed_registration_id)
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancelled_followup_returns_timeout_without_consuming_pending_registration() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        let app = router(state.clone());
        let node_key_hex = "cf".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "cancelled-followup" },
        });

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let first: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let auth_id = first
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .unwrap();
        let registration_id = auth_id.strip_prefix(AUTH_ID_PREFIX).unwrap();

        let followup_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Followup": first.auth_url,
            "Hostinfo": { "Hostname": "cancelled-followup" },
        });
        let cancellation = NoiseRequestCancellation::new();
        cancellation.cancel();
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&followup_body).unwrap(),
            ))
            .unwrap();
        req.extensions_mut().insert(cancellation);

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let timed_out: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(timed_out.error, "registration timed out");
        assert!(timed_out.auth_url.is_empty());
        assert!(
            state.registration_cache.get(registration_id).is_some(),
            "cancelled follow-up must not consume the pending auth session"
        );
    }

    #[tokio::test]
    async fn missing_authkey_interactive_registration_applies_node_expiry_default() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let app = router(state.clone());
        let node_key_hex = "d4".repeat(32);
        let before = chrono::Utc::now();
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending-default-expiry" },
        });

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let auth_id = rr
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .expect("configured web registration AuthURL");
        let registration_id = auth_id
            .strip_prefix(AUTH_ID_PREFIX)
            .expect("AuthURL uses current-upstream auth ID prefix");
        let pending = state.registration_cache.get(registration_id).unwrap();
        let expiry = pending.expiry.expect("node.expiry default applied");

        assert!(expiry >= before + chrono::Duration::seconds(3600));
        assert!(expiry <= chrono::Utc::now() + chrono::Duration::seconds(3600));
    }

    #[tokio::test]
    async fn expired_followup_restarts_web_registration_flow() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        state.registration_cache = Arc::new(crate::tailscale_wire::RegistrationCache::with_tuning(
            Duration::from_millis(10),
            Duration::from_millis(20),
        ));
        let app = router(state.clone());
        let node_key_hex = "dd".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending-peer" },
        });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let first: RegisterResponse = serde_json::from_slice(&raw).unwrap();

        let followup_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Followup": first.auth_url,
            "Hostinfo": { "Hostname": "pending-peer" },
        });
        let followup_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&followup_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(followup_resp.status(), StatusCode::OK);
        let raw = to_bytes(followup_resp.into_body(), 8192).await.unwrap();
        let restarted: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(!restarted.machine_authorized);
        assert_ne!(restarted.auth_url, first.auth_url);
        assert!(
            restarted
                .auth_url
                .starts_with("https://headscale.example/register/")
        );
        assert_eq!(state.registration_cache.len(), 1);
    }

    /// Flat v1.78+ path: NodeKey lives in the body, not the URL.
    #[tokio::test]
    async fn flat_register_extracts_node_key_from_body() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-flat-alice";
        redeemer.insert(authkey, "alice");
        let app = router(state.clone());
        let node_key_hex = "11".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert_eq!(rr.login.login_name, "alice");
        // Machine registry remembers the registration under the
        // body-supplied NodeKey hex.
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.user, "alice");
    }

    /// Keyed path still works after the flat-path addition (regression
    /// guard for the additive-router design).
    #[tokio::test]
    async fn keyed_register_still_works_after_flat_addition() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-keyed-regression";
        redeemer.insert(authkey, "bob");
        let app = router(state.clone());
        let node_key_hex = "22".repeat(32);
        let body = req_body(&node_key_hex, authkey);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Flat path follows headscale-go: a missing NodeKey is still parsed,
    /// and auth failures come back in the RegisterResponse error field.
    #[tokio::test]
    async fn flat_register_missing_node_key_uses_register_response_error() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let body = serde_json::json!({
            "Version": 113,
            "Auth": { "AuthKey": "anything" },
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/register")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rr.error, "preauth key not recognised");
    }

    #[tokio::test]
    async fn rejects_mismatched_node_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-mismatch-test";
        redeemer.insert(authkey, "u");
        let app = router(state);
        let body = req_body(&"aa".repeat(32), authkey);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{}/register", "bb".repeat(32)))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
