//! `POST /machine/{node_key}/register` — initial join handler.
//!
//! Validates a presented preauth key against [`PreauthMinter`],
//! allocates a tailnet IPv4 for the new machine, persists the
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
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// Decode a `RegisterRequest` from a raw body without requiring the
/// `Content-Type: application/json` header. Stock `tailscale up`
/// (via controlhttp over the noise tunnel) sends register payloads
/// with no `Content-Type` set, so the axum `Json` extractor rejects
/// them with HTTP 415. We use a `Bytes` extractor + manual
/// `serde_json::from_slice` to mirror what upstream's
/// `gorilla/mux`-routed handlers accept.
fn parse_register_body(raw: &[u8]) -> Result<RegisterRequest, axum::response::Response> {
    serde_json::from_slice::<RegisterRequest>(raw).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid RegisterRequest JSON: {e}"),
            }),
        )
            .into_response()
    })
}

use super::noise::NoisePeerMachineKey;
use super::routes::{auto_approved_routes_for_node, normalize_routes};
use super::wire::{
    HostInfo, MapNode, RegisterRequest, RegisterResponse, SimpleLogin, SimpleUser,
    is_supported_capability_version, stable_id_from_key, strip_key_prefix,
    unsupported_client_error,
};
use super::{MachineRecord, RedeemError, RegistrationWaitOutcome, WireState};

const REGISTRATION_ID_RANDOM_BYTES: usize = 18;
const REGISTRATION_ID_LENGTH: usize = 24;

pub(crate) const CAPABILITY_ADMIN: &str = "https://tailscale.com/cap/is-admin";
pub(crate) const CAPABILITY_FILE_SHARING: &str = "https://tailscale.com/cap/file-sharing";
pub(crate) const CAPABILITY_SSH: &str = "https://tailscale.com/cap/ssh";

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub async fn handle_register(
    State(state): State<WireState>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let body = match parse_register_body(&raw) {
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
    register_inner(state, body_node_key_hex, machine_key, body).await
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
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let body = match parse_register_body(&raw) {
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
    if body_node_key_hex.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "missing NodeKey in body".into(),
            }),
        )
            .into_response();
    }
    register_inner(state, body_node_key_hex, machine_key, body).await
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
) -> axum::response::Response {
    let authkey = body.auth.as_ref().map_or("", |a| a.auth_key.as_str());
    let requested_tags = requested_tags_for_body(&body);
    let now = chrono::Utc::now();

    if let Some(expiry) = body.expiry
        && expiry <= now
        && let Some(record) = state.machines.get(&node_key_hex)
    {
        if let Err(resp) = validate_existing_machine_key(&machine_key_hex, &record) {
            return resp;
        }
        return logout_existing_node(&state, &node_key_hex, &record, expiry);
    }

    if authkey.is_empty() {
        if let Some(record) = state.machines.get(&node_key_hex) {
            if let Err(resp) = validate_existing_machine_key(&machine_key_hex, &record) {
                return resp;
            }
            if record.is_expired_at(now) {
                return Json(node_key_expired_response(false)).into_response();
            }
            if let Some(expiry) = body.expiry {
                if expiry > now {
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

            match state
                .registration_cache
                .wait_for_registration(&registration_id)
                .await
            {
                RegistrationWaitOutcome::Registered(record) => {
                    return Json(register_response_for_record(&record)).into_response();
                }
                RegistrationWaitOutcome::ApprovedWithoutNode
                | RegistrationWaitOutcome::Expired
                | RegistrationWaitOutcome::Missing => {
                    return register_interactive(state, node_key_hex, machine_key_hex, body).await;
                }
                RegistrationWaitOutcome::Rejected(reason) => {
                    return register_error_response(reason);
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
            let Some((existing_node_key, _)) = state
                .machines
                .get_by_machine_key_for_user(&machine_key_hex, &ok.user)
            else {
                return preauth_error_response(err);
            };
            if existing_node_key != node_key_hex {
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
    if let Some((old_node_key_hex, _)) = existing_machine.as_ref()
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
    let ipv4 = if let Some((_, existing)) = existing_machine.as_ref() {
        existing.ipv4
    } else {
        match allocate_register_ip(&state, &format!("{user}:{node_key_hex}")) {
            Ok(ip) => ip,
            Err(resp) => return resp,
        }
    };
    let addr = ipv4.to_string();
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
        effective_authkey_expiry(body.expiry, now)
    } else {
        existing_machine
            .as_ref()
            .and_then(|(_, existing)| existing.expiry)
    };
    let rec = MachineRecord {
        node_key_hex: node_key_hex.clone(),
        machine_key_hex,
        user,
        hostname,
        os,
        os_version,
        host_info,
        ipv4,
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
            state.machines.replace_node_key(
                old_node_key_hex,
                saved.record.node_key_hex.clone(),
                saved.record,
            );
        } else {
            state
                .machines
                .upsert(saved.record.node_key_hex.clone(), saved.record);
        }
    } else if let Some((old_node_key_hex, _)) = existing_machine {
        state
            .machines
            .replace_node_key(&old_node_key_hex, node_key_hex.clone(), rec);
    } else {
        state.machines.upsert(node_key_hex.clone(), rec);
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
    let ipv4 = match allocate_register_ip(&state, &format!("pending:{node_key_hex}")) {
        Ok(ip) => ip,
        Err(resp) => return resp,
    };
    let now = chrono::Utc::now();
    let registration_id = new_registration_id();
    let record = MachineRecord {
        node_key_hex,
        machine_key_hex,
        user: String::new(),
        hostname,
        os,
        os_version,
        host_info,
        ipv4,
        disco_key: None,
        endpoints: Vec::new(),
        home_derp: 0,
        expiry: effective_authkey_expiry(body.expiry, now),
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
        .map(|h| normalize_routes(&h.routable_ips))
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
    available_routes: &[String],
    auto_approved_routes: Vec<String>,
) -> Vec<String> {
    let available: BTreeSet<&str> = available_routes.iter().map(String::as_str).collect();
    let mut merged: BTreeSet<String> = existing_approved_routes
        .iter()
        .filter(|route| available.contains(route.as_str()))
        .cloned()
        .collect();
    merged.extend(auto_approved_routes);
    merged.into_iter().collect()
}

fn effective_authkey_expiry(
    expiry: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    expiry.filter(|expiry| *expiry > now)
}

fn preauth_error_response(err: RedeemError) -> axum::response::Response {
    let error = match err {
        RedeemError::Unknown => "preauth key not recognised",
        RedeemError::Expired => "preauth key expired",
        RedeemError::AlreadyUsed => "preauth key already used",
    };
    register_error_response(error)
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
) -> Result<(), axum::response::Response> {
    if record.machine_key_hex == presented_machine_key_hex {
        return Ok(());
    }

    Err(register_error_response(
        "node exist with different machine key",
    ))
}

fn reject_unsupported_capability(version: u32) -> Result<(), axum::response::Response> {
    if is_supported_capability_version(version) {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: unsupported_client_error(version),
        }),
    )
        .into_response())
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

fn allocate_register_ip(
    state: &WireState,
    alloc_input: &str,
) -> Result<Ipv4Addr, axum::response::Response> {
    state.ip_allocator.allocate(alloc_input).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                error: format!("ip allocation failed: {e}"),
            }),
        )
            .into_response()
    })
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
    match state.public_control_url.as_deref() {
        Some(url) if !url.is_empty() => {
            format!("{}/register/{registration_id}", url.trim_end_matches('/'))
        }
        _ => format!("/register/{registration_id}"),
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

    if registration_id.contains('/') || registration_id.len() != REGISTRATION_ID_LENGTH {
        return Err("invalid registration ID");
    }

    Ok(registration_id.to_string())
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
            format!("{label}.{domain}")
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
    let id = stable_id_from_key(&rec.node_key_hex);
    let stable_id = format!("n{id}");
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
    MapNode {
        id,
        stable_id,
        name,
        user,
        key: format!("nodekey:{}", rec.node_key_hex),
        machine,
        addresses: vec![format!("{}/32", rec.ipv4)],
        allowed_ips: std::iter::once(format!("{}/32", rec.ipv4))
            .chain(rec.approved_routes.iter().cloned())
            .collect(),
        primary_routes: rec.approved_routes.clone(),
        hostinfo: rec.host_info_for_node(),
        created: Some(rec.created_at),
        key_expiry: rec.expiry,
        cap: 0,
        tags: rec.forced_tags.clone(),
        last_seen: Some(rec.last_seen),
        online: Some(!expired),
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
        (CAPABILITY_FILE_SHARING.to_string(), Vec::new()),
        (CAPABILITY_SSH.to_string(), Vec::new()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRegistrationStore, MachineRegistry, PersistedMachineRegistration, RedeemOk,
        WireState,
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
            derp_map: Arc::new(crate::tailscale_wire::wire::DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
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
            record.ipv4 = Ipv4Addr::new(100, 64, 9, 9);
            Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: None,
            })
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

        assert_eq!(node.allowed_ips, vec!["100.64.0.8/32", "10.0.0.0/24"]);
        assert_eq!(node.primary_routes, vec!["10.0.0.0/24"]);
        assert_eq!(
            node.hostinfo.routable_ips,
            vec!["10.0.0.0/24", "fd7a:115c:a1e0::/48"]
        );
        assert_eq!(node.hostinfo.os, "linux");
        assert_eq!(node.hostinfo.os_version, "6.8");
    }

    #[tokio::test]
    async fn oidc_router_register_starts_auth_code_flow() {
        let (state, _redeemer, _dir) = fixture();
        let oidc = oidc_runtime();
        let app = router_with_oidc(state, oidc.clone());
        let registration_id = "a".repeat(24);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/register/{registration_id}"))
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
        assert_eq!(
            oidc.registration(state).unwrap().registration_id,
            registration_id
        );
        assert_eq!(
            resp.headers()
                .get_all(axum::http::header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
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
        assert_eq!(
            registration_id_from_followup(&format!("/register/{id}")).unwrap(),
            id
        );
        assert_eq!(
            registration_id_from_followup(&format!("https://headscale.example/register/{id}"))
                .unwrap(),
            id
        );
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
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(ev["error"], "unsupported client version:  (112)");
        assert!(state.machines.get(&node_key_hex).is_none());
        assert!(redeemer.contains(authkey));
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
        assert!(rec.ipv4.octets()[0] == 100);
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
        assert_eq!(rec.ipv4, Ipv4Addr::new(100, 64, 9, 9));
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
        assert_eq!(raw.ipv4, Some(first_ip.to_string()));
    }

    #[tokio::test]
    async fn authkey_tagged_preauth_disables_requested_expiry() {
        let (state, redeemer, _dir) = fixture();
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
    async fn authkey_untagged_preauth_ignores_go_zero_expiry() {
        let (state, redeemer, _dir) = fixture();
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
        assert!(
            rec.expiry.is_none(),
            "Go's zero time should not create an already-expired node"
        );
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
        assert_eq!(rotated.hostname, "peer-rotated");
        assert_eq!(rotated.ipv4, first_ipv4);
        assert_eq!(rotated.created_at, first_created_at);
        assert_eq!(rotated.disco_key.as_deref(), Some("discokey:old"));
        assert_eq!(rotated.endpoints, vec!["198.51.100.10:41641"]);
        assert_eq!(
            rotated.available_routes,
            vec!["10.40.0.0/24", "10.42.0.0/24"]
        );
        assert_eq!(rotated.approved_routes, vec!["10.40.0.0/24"]);
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
        let (state, redeemer, _dir) = fixture();
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
        let registration_id = rr
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .unwrap();
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
        assert_eq!(rr.error, "node exist with different machine key");
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
        let registration_id = rr
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .expect("configured web registration AuthURL");
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

    /// Flat path rejects an empty NodeKey body.
    #[tokio::test]
    async fn flat_register_rejects_missing_node_key() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": "",
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
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
