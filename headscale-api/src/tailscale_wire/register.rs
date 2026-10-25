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
//! - **User IDs:** persistent registration carries the database owner ID.
//!   Wire-only embedders without an assigned ID use the legacy user-label
//!   hash, which changes if that label changes.

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
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Decode a `RegisterRequest` from a raw body without requiring the
/// `Content-Type: application/json` header. Stock `tailscale up`
/// (via controlhttp over the noise tunnel) sends register payloads
/// with no `Content-Type` set, so the axum `Json` extractor rejects
/// them with HTTP 415. We use a `Bytes` extractor with
/// the shared Go struct decoder to mirror what upstream's
/// `gorilla/mux`-routed handlers accept.
fn parse_register_body(
    raw: &[u8],
) -> Result<(RegisterRequest, serde_json::Value), RegisterBodyError> {
    super::request_json::register(raw).map_err(|error| RegisterBodyError {
        version: error.version,
        error: error.message,
    })
}

#[derive(Debug)]
struct RegisterBodyError {
    version: u32,
    error: String,
}

fn parse_register_or_go_error(
    raw: &[u8],
) -> Result<(RegisterRequest, serde_json::Value), axum::response::Response> {
    match parse_register_body(raw) {
        Ok(body) => Ok(body),
        Err(RegisterBodyError { version, error }) => {
            reject_unsupported_capability(version)?;
            Err(register_error_response(error))
        }
    }
}

use super::noise::{NoisePeerMachineKey, NoiseRequestCancellation};
use super::wire::{
    HostInfo, MapNode, RegisterRequest, RegisterResponse, SimpleLogin, SimpleUser, ZERO_DISCO_KEY,
    is_supported_capability_version, strip_key_prefix, unsupported_client_error,
};
use super::{
    MachineRecord, RegistrationAdmission, RegistrationSource, RegistrationWaitOutcome, WireState,
};

const REGISTRATION_ID_RANDOM_BYTES: usize = 18;
const AUTH_ID_PREFIX: &str = "hskey-authreq-";
const REGISTRATION_ID_LENGTH: usize = 24;
const AUTH_ID_LENGTH: usize = AUTH_ID_PREFIX.len() + REGISTRATION_ID_LENGTH;
const REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH: &str =
    "node exists with a different machine key";
const REGISTER_LOGOUT_MACHINE_KEY_MISMATCH: &str = "node exist with different machine key";

/// A tagged PAK is bound to the machine, not its creating user. Go prefers
/// that machine's existing tagged node; with no tagged node, it may convert a
/// single user-owned node. An ordinary PAK may also re-register a tagged
/// node, retaining its tagged ownership. Reject ambiguous conversions.
fn existing_machine_for_preauth(
    state: &WireState,
    machine_key_hex: &str,
    user: &str,
    user_id: Option<u64>,
    tagged_key: bool,
) -> Result<Option<(String, MachineRecord)>, &'static str> {
    if user_id.is_none() && user.is_empty() && !tagged_key {
        return Ok(None);
    }
    let snapshot = state.machines.snapshot_with_metadata();
    if user_id.is_some() || (!tagged_key && !user.is_empty()) {
        let mut owned = snapshot.iter().filter(|(_, node)| {
            node.machine_key_hex == machine_key_hex
                && node.forced_tags.is_empty()
                && user_id.map_or_else(|| node.user == user, |id| node.user_id == Some(id))
        });
        if let Some((node_key, existing)) = owned.next() {
            if owned.next().is_some() {
                return Err("machine key maps to ambiguous node ownership");
            }
            return Ok(Some((node_key.clone(), existing.clone())));
        }
    }
    let matches = snapshot
        .iter()
        .filter(|(_, record)| record.machine_key_hex == machine_key_hex)
        .map(|(node_key, record)| (node_key.clone(), record.clone()))
        .collect::<Vec<_>>();
    let tagged = matches
        .iter()
        .filter(|(_, record)| !record.forced_tags.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    if tagged.len() > 1 {
        return Err("machine key maps to ambiguous node ownership");
    }
    if let Some(existing) = tagged.into_iter().next() {
        return Ok(Some(existing));
    }
    if !tagged_key || user_id.is_some() {
        return Ok(None);
    }
    let matches = matches
        .into_iter()
        .filter(|(_, record)| {
            record.user_id.is_some_and(|id| id != 0)
                || (record.user_id.is_none()
                    && !record.user.is_empty()
                    && snapshot.native_user_association_id(record).is_none())
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err("machine key maps to ambiguous node ownership");
    }
    Ok(matches.into_iter().next())
}
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
    source: Option<Extension<RegistrationSource>>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let (body, hostinfo) = match parse_register_or_go_error(&raw) {
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
    Box::pin(register_inner_with_hostinfo(
        state,
        body_node_key_hex,
        machine_key,
        body,
        hostinfo,
        cancellation.map(|Extension(cancellation)| cancellation),
        source.map(|Extension(source)| source),
    ))
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
    source: Option<Extension<RegistrationSource>>,
    raw: Bytes,
) -> axum::response::Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let (body, hostinfo) = match parse_register_or_go_error(&raw) {
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
    Box::pin(register_inner_with_hostinfo(
        state,
        body_node_key_hex,
        machine_key,
        body,
        hostinfo,
        cancellation.map(|Extension(cancellation)| cancellation),
        source.map(|Extension(source)| source),
    ))
    .await
}

/// Shared logic between the keyed and flat register handlers.
///
/// `node_key_hex` is the canonical, prefix-stripped form. The body's
/// own NodeKey is also re-parsed here (and used to populate the
/// `MachineRecord`); callers are expected to have already validated
/// that the two agree (for the keyed path) or supplied the body's value
/// directly (for the flat path).
#[cfg(test)]
async fn register_inner(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    cancellation: Option<NoiseRequestCancellation>,
) -> axum::response::Response {
    register_inner_from(
        state,
        node_key_hex,
        machine_key_hex,
        body,
        cancellation,
        None,
    )
    .await
}

#[cfg(test)]
async fn register_inner_from(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    cancellation: Option<NoiseRequestCancellation>,
    source: Option<RegistrationSource>,
) -> axum::response::Response {
    let hostinfo = serde_json::to_value(&body.hostinfo).expect("HostInfo JSON primitives");
    Box::pin(register_inner_with_hostinfo(
        state,
        node_key_hex,
        machine_key_hex,
        body,
        hostinfo,
        cancellation,
        source,
    ))
    .await
}

async fn register_inner_with_hostinfo(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    requested_hostinfo: serde_json::Value,
    cancellation: Option<NoiseRequestCancellation>,
    source: Option<RegistrationSource>,
) -> axum::response::Response {
    let has_auth = body.auth.is_some();
    let authkey = body.auth.as_ref().map_or("", |a| a.auth_key.as_str());
    let requested_tags = requested_tags_for_body(&body);
    let now = chrono::Utc::now();

    if let Some(expiry) = body.expiry
        && !is_go_zero_expiry(expiry)
        && expiry < now
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
            return register_json_response(&node_key_expired_response(false));
        }
        return logout_existing_node(&state, &node_key_hex, &record, expiry).await;
    }

    // Admission gate. Deliberately after the logout branch — a node being
    // deregistered must be able to finish even once its admission is gone —
    // and ahead of everything else, so a refused key cannot acquire a
    // record, an address, or a place in any peer's netmap by any path
    // (auth key, interactive login, followup poll, existing-node refresh).
    //
    // A logout-shaped request that carries no auth key is exempt even when
    // we hold no record for the key (the branch above only covers keys we
    // know): it can never do more than drop access, and refusing it turns a
    // plain `tailscale logout` into an error for the operator. The
    // no-auth-key condition matters — an expiry in the past *plus* an auth
    // key is a registration attempt wearing a logout's clothes.
    let is_logout_attempt = authkey.is_empty()
        && body
            .expiry
            .is_some_and(|expiry| !is_go_zero_expiry(expiry) && expiry < now);
    if !is_logout_attempt && let Some(gate) = state.registration_gate.as_ref() {
        let hostname = body
            .hostinfo
            .as_ref()
            .map(|info| info.hostname.as_str())
            .filter(|name| !name.is_empty());
        if let Err(reason) = gate
            .admit(RegistrationAdmission {
                node_key_hex: &node_key_hex,
                machine_key_hex: &machine_key_hex,
                hostname,
            })
            .await
        {
            // The machine key is in the line on purpose: it is the device's
            // stable identity (node keys rotate on every refused attempt),
            // so it is what an operator can act on.
            tracing::info!(
                target: "tailscale_wire::register",
                node_key = %node_key_hex,
                machine_key = %machine_key_hex,
                hostname = hostname.unwrap_or("-"),
                reason = %reason,
                "registration refused by the admission gate"
            );
            return register_error_response(reason);
        }
    }

    if !has_auth && let Some(record) = state.machines.get(&node_key_hex) {
        if let Err(resp) = validate_existing_machine_key(
            &machine_key_hex,
            &record,
            REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH,
        ) {
            return resp;
        }
        if record.is_expired_at(now) {
            return register_json_response(&node_key_expired_response(false));
        }
        if let Some(expiry) = body.expiry {
            if is_go_zero_expiry(expiry) {
                return register_json_response(&register_response_for_live_record(
                    &state.machines,
                    &record,
                ));
            } else if expiry > now {
                return register_error_response("extending key is not allowed");
            }
        } else {
            return register_json_response(&register_response_for_live_record(
                &state.machines,
                &record,
            ));
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
            let wait = async {
                match registration_id.as_deref() {
                    Some(id) => registration_cache.wait_for_registration(id).await,
                    // Generated cache IDs are ASCII. A shape-valid byte ID
                    // outside UTF-8 cannot alias any generated registration.
                    None => RegistrationWaitOutcome::Missing,
                }
            };
            tokio::pin!(wait);
            if let Some(cancellation) = cancellation {
                tokio::select! {
                    // If authorization and disconnect become ready together,
                    // deliver the completed registration as pinned Go does.
                    biased;
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
                if let Err(resp) = validate_existing_machine_key(
                    &machine_key_hex,
                    &record,
                    REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH,
                ) {
                    return resp;
                }
                return register_json_response(&register_response_for_live_record(
                    &state.machines,
                    &record,
                ));
            }
            RegistrationWaitOutcome::ApprovedWithoutNode
            | RegistrationWaitOutcome::Rejected(_)
            | RegistrationWaitOutcome::Expired
            | RegistrationWaitOutcome::Missing => {
                return register_interactive(
                    state,
                    node_key_hex,
                    machine_key_hex,
                    body,
                    requested_hostinfo,
                    source,
                )
                .await;
            }
        }
    }
    if authkey.is_empty() {
        return register_interactive(
            state,
            node_key_hex,
            machine_key_hex,
            body,
            requested_hostinfo,
            source,
        )
        .await;
    }

    // Go's accepted auth-key handler keeps running after the HTTP caller
    // disconnects. Own lookup, validation, planning and publication together,
    // including time spent waiting for the registration locks or bcrypt.
    match super::complete_state_mutation(Box::pin(register_auth_key(
        state,
        node_key_hex,
        machine_key_hex,
        body,
        requested_hostinfo,
        requested_tags,
        now,
    )))
    .await
    {
        Ok(response) => response,
        Err(error) => register_error_response(format!("finishing auth-key registration: {error}")),
    }
}

async fn register_auth_key(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    requested_hostinfo: serde_json::Value,
    requested_tags: Vec<String>,
    _now: chrono::DateTime<chrono::Utc>,
) -> axum::response::Response {
    let authkey = body.auth.as_ref().map_or("", |a| a.auth_key.as_str());
    let registration_guard = state.machines.lock_registration(&machine_key_hex).await;
    let node_key_registration_guard = state
        .machines
        .lock_node_key_registration(&node_key_hex)
        .await;
    // A still-authorized node waking with its current key does not spend a
    // new PAK. Expiry, rotation, ownership conversion and retagging require
    // fresh validation even when the client reuses its node key.
    let lookup = match state.preauth.lookup_for_registration(authkey).await {
        Ok(lookup) => lookup,
        Err(error) => return preauth_error_response(error),
    };
    let refresh = if let Some(lookup) = &lookup {
        let key = &lookup.metadata;
        match existing_machine_for_preauth(
            &state,
            &machine_key_hex,
            &key.user,
            key.user_id,
            !key.tags.is_empty(),
        ) {
            Ok(Some((current_key, current)))
                if current_key == node_key_hex
                    && existing_node_can_refresh_with_key(&current, key, chrono::Utc::now()) =>
            {
                Some(key.clone())
            }
            Ok(_) => None,
            Err(error) => return register_error_response(error),
        }
    } else {
        None
    };
    let require_fresh = refresh.is_none();
    let atomic_registration = state.preauth.supports_deferred_redemption()
        && state
            .registration_store
            .as_ref()
            .is_some_and(|store| store.supports_atomic_auth_key_registration());
    let redeemed = match refresh {
        Some(key) => key,
        None => match if atomic_registration {
            if let Some(lookup) = &lookup
                && let Some(valid) = lookup.validation_result()
            {
                valid.map(|()| lookup.metadata.clone())
            } else {
                state.preauth.validate_for_registration(authkey).await
            }
        } else {
            state.preauth.redeem_for_registration(authkey).await
        } {
            Ok(ok) => ok,
            Err(err) => return preauth_error_response(err),
        },
    };
    let user = redeemed.user.clone();

    let RegisterHostInfoParts {
        mut host_info,
        hostname,
        os,
        os_version,
        available_routes,
        ssh_host_keys,
    } = match register_hostinfo_parts(&body) {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };

    let existing_machine = match existing_machine_for_preauth(
        &state,
        &machine_key_hex,
        &user,
        redeemed.user_id,
        !redeemed.tags.is_empty(),
    ) {
        Ok(existing) => existing,
        Err(error) => return register_error_response(error),
    };
    if existing_machine.is_none() && !requested_tags.is_empty() {
        return invalid_requested_tags_response(
            body.hostinfo
                .as_ref()
                .map_or(&[], |info| info.request_tags.as_slice()),
        );
    }
    if let Err(error) = state
        .machines
        .validate_registration_node_key(&node_key_hex, &machine_key_hex)
    {
        return register_error_response(format!("handling register with auth key: {error}"));
    }
    let (ipv4, ipv6) = if let Some((_, existing)) = existing_machine.as_ref() {
        (existing.ipv4, existing.ipv6)
    } else {
        match allocate_register_ips(&state, &format!("{user}:{node_key_hex}")) {
            Ok(ips) => ips,
            Err(resp) => return resp,
        }
    };
    // A different tagged preauth key is an explicit retag request. The
    // current key, on the other hand, must preserve any admin tag override
    // during a container restart. Go v0.29.3 made this distinction for
    // already-tagged nodes, and also converts an untagged node in place.
    let forced_tags = existing_machine.as_ref().map_or_else(
        || redeemed.tags.clone(),
        |(_, existing)| {
            let tagged_key_changed = !redeemed.tags.is_empty()
                && (existing.forced_tags.is_empty()
                    || redeemed
                        .auth_key_id
                        .is_some_and(|id| existing.auth_key_id != Some(id)));
            if tagged_key_changed {
                redeemed.tags.clone()
            } else {
                existing.forced_tags.clone()
            }
        },
    );
    let approved_routes = existing_machine
        .as_ref()
        .map(|(_, existing)| existing.approved_routes.clone())
        .unwrap_or_default();
    // P1 lifecycle: stamp `created_at` / `last_seen` at registration
    // time + propagate the preauth's `ephemeral` flag. `forced_tags`
    // adopts the preauth's tag list verbatim so the very first /map
    // call emits the operator's intended tags; later
    // `POST /api/v1/machines/{id}/tags` overrides on demand.
    let now = chrono::Utc::now();
    let created_at = existing_machine
        .as_ref()
        .map_or(now, |(_, existing)| existing.created_at);
    let ephemeral = redeemed.ephemeral;
    let auth_key_id = redeemed.auth_key_id.or_else(|| {
        existing_machine
            .as_ref()
            .and_then(|(_, existing)| existing.auth_key_id)
    });
    let node_id = existing_machine
        .as_ref()
        .map(|(key, existing)| existing.stable_node_id_for_key(key));
    let user_id = if forced_tags.is_empty() {
        redeemed.user_id.or_else(|| {
            existing_machine
                .as_ref()
                .and_then(|(_, existing)| existing.user_id)
        })
    } else {
        None
    };
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
    let user_provider = existing_machine
        .as_ref()
        .map_or_else(String::new, |(_, existing)| existing.user_provider.clone());
    let user_created_at = existing_machine
        .as_ref()
        .and_then(|(_, existing)| existing.user_created_at);
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
    let expiry = if forced_tags.is_empty() {
        effective_register_expiry(
            body.expiry,
            configured_node_expiry(state.runtime_config.as_ref(), now),
        )
    } else {
        // Tagged nodes do not acquire a client/default expiry, but an
        // operator-scheduled future expiry belongs to the node and survives
        // retagging. Clear only a stale logout/expired timestamp.
        existing_machine
            .as_ref()
            .and_then(|(_, existing)| existing.expiry.filter(|expiry| *expiry >= now))
    };
    let given_name = existing_machine.as_ref().map_or_else(
        || super::wire::sanitize_hostname_for_given_name(&hostname),
        |(_, existing)| existing.hostname.clone(),
    );
    let mut rec = MachineRecord {
        node_id,
        auth_key_id,
        node_key_hex: node_key_hex.clone(),
        machine_key_hex,
        user: if forced_tags.is_empty() {
            user
        } else {
            String::new()
        },
        user_id,
        user_display_name,
        user_profile_pic_url,
        user_provider,
        user_created_at,
        hostname: given_name,
        raw_hostname: hostname,
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

    if rec.is_tagged() {
        rec.clear_user_identity();
    }

    let previous_hostinfo = match existing_machine.as_ref() {
        Some((_, existing)) => match state.machines.map_hostinfo_value(existing) {
            Ok(value) => Some(value),
            Err(error) => {
                return register_error_response(format!("encoding existing Hostinfo: {error}"));
            }
        },
        None => None,
    };
    let native_hostinfo = match super::hostinfo::registration_value(
        &requested_hostinfo,
        &rec.host_info_for_node(),
        previous_hostinfo
            .as_ref()
            .and_then(|value| value.get("NetInfo")),
    ) {
        Ok(value) => value,
        Err(error) => {
            return register_error_response(format!("encoding registration Hostinfo: {error}"));
        }
    };

    if let Some(store) = &state.registration_store {
        let store = store.clone();
        let policy = state.policy.clone();
        let machines = state.machines.clone();
        let candidate = authkey.to_owned();
        let auth_key_id = redeemed.auth_key_id;
        let completed = super::complete_state_mutation(async move {
            let _registration = registration_guard;
            let _node_key_registration = node_key_registration_guard;
            #[cfg(feature = "admin")]
            let _publication = machines.registration_publication_scope(&rec);
            let saved = if atomic_registration {
                store
                    .create_or_update_auth_key_registration_atomic_with_lookup(
                        rec,
                        policy.as_ref(),
                        &candidate,
                        auth_key_id,
                        require_fresh,
                        Some(native_hostinfo),
                        lookup,
                    )
                    .await?
            } else {
                store
                    .create_or_update_auth_key_registration_with_hostinfo(
                        rec,
                        policy.as_ref(),
                        auth_key_id,
                        Some(native_hostinfo),
                    )
                    .await
                    .map_err(super::AuthKeyRegistrationError::Storage)?
            };
            let registered_key = saved.record.node_key_hex.clone();
            if let Some(old_node_key) = saved.replaced_node_key_hex.as_deref() {
                machines
                    .try_replace_node_key_auth_completion(
                        old_node_key,
                        registered_key.clone(),
                        saved.record,
                    )
                    .await
                    .map_err(super::AuthKeyRegistrationError::Storage)?;
            } else {
                machines
                    .try_upsert_auth_completion(registered_key.clone(), saved.record)
                    .await
                    .map_err(super::AuthKeyRegistrationError::Storage)?;
            }
            let record = machines.get(&registered_key).ok_or_else(|| {
                super::AuthKeyRegistrationError::Storage(
                    "registered node disappeared before publication".into(),
                )
            })?;
            auto_approve_registered_routes(&machines, &policy, Some(store.as_ref()), &record)
                .await
                .map_err(|error| {
                    super::AuthKeyRegistrationError::Storage(format!(
                        "auto approving routes: {error}"
                    ))
                })?;
            Ok(record)
        })
        .await;
        return match completed {
            Ok(Ok(record)) => {
                register_json_response(&register_response_for_live_record(&state.machines, &record))
            }
            Ok(Err(super::AuthKeyRegistrationError::Credential(error))) => {
                preauth_error_response(error)
            }
            Ok(Err(super::AuthKeyRegistrationError::Storage(error))) => {
                register_error_response(format!("handling register with auth key: {error}"))
            }
            Err(error) => register_error_response(format!("finishing node registration: {error}")),
        };
    }
    match state
        .machines
        .commit_volatile_auth_registration_with_hostinfo_async(
            existing_machine.as_ref().map(|(key, _)| key.as_str()),
            rec,
            Some(native_hostinfo),
        )
        .await
    {
        Ok(record) => {
            if let Err(error) =
                auto_approve_registered_routes(&state.machines, &state.policy, None, &record).await
            {
                return register_error_response(format!(
                    "handling register with auth key: auto approving routes: {error}"
                ));
            }
            register_json_response(&register_response_for_live_record(&state.machines, &record))
        }
        Err(error) => (
            if matches!(&error, super::RegistryMutationError::Policy(_)) {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            },
            Json(ErrorBody {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

/// headscale-go `handleRegisterWithAuthKey` runs `State.AutoApproveRoutes`
/// once `HandleNodeFromPreAuthKey` has put the node in the NodeStore and the
/// policy manager (the approvers resolve against the node's own addresses).
/// A changed approval is applied like `State.SetApprovedRoutes`: NodeStore
/// first, then the database row and policy refresh, then the
/// `change.PolicyChange()` sent after the registration's own change.
/// Callers hold the per-machine registration guard, as runtime sync requires.
/// The OIDC / CLI web-registration completion (`web_registration.rs`) runs the
/// same step after `HandleNodeFromAuthPath`.
pub(super) async fn auto_approve_registered_routes(
    machines: &super::MachineRegistry,
    policy: &crate::policy::PolicyStore,
    store: Option<&dyn super::MachineRegistrationStore>,
    record: &MachineRecord,
) -> Result<(), String> {
    let user = (!record.user.is_empty()).then_some(record.user.as_str());
    let approved = super::routes::auto_approved_routes_for_node(
        policy,
        &record.address_strings(),
        user,
        record.user_id,
        &record.forced_tags,
        &record.approved_routes,
        &record.available_routes,
    )?;
    if approved == record.approved_routes {
        return Ok(());
    }
    let node_id = record.stable_node_id_for_key(&record.node_key_hex);
    if machines
        .apply_policy_route_approvals(vec![(node_id, approved)])
        .is_empty()
    {
        return Err(format!("node no longer exists in NodeStore: {node_id}"));
    }
    if let Some(store) = store {
        let updated = machines
            .get(&record.node_key_hex)
            .ok_or_else(|| format!("node no longer exists in NodeStore: {node_id}"))?;
        store.sync_runtime_machine_state(updated, policy).await?;
    }
    machines.try_refresh_policy_node_inputs()?;
    machines.wake_policy_change(None);
    Ok(())
}

async fn register_interactive(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    body: RegisterRequest,
    requested_hostinfo: serde_json::Value,
    source: Option<RegistrationSource>,
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
    let now = chrono::Utc::now();
    let registration_id = new_registration_id();
    let expiry = if requested_tags.is_empty() {
        body.expiry.filter(|expiry| !is_go_zero_expiry(*expiry))
    } else {
        None
    };
    let home_derp = host_info
        .net_info
        .as_ref()
        .map_or(0, |info| info.preferred_derp);
    let record = MachineRecord {
        node_id: None,
        auth_key_id: None,
        node_key_hex,
        machine_key_hex,
        user: String::new(),
        user_id: None,
        user_display_name: String::new(),
        user_profile_pic_url: String::new(),
        user_provider: String::new(),
        user_created_at: None,
        raw_hostname: hostname.clone(),
        hostname,
        os,
        os_version,
        host_info,
        ipv4: None,
        ipv6: None,
        disco_key: None,
        endpoints: Vec::new(),
        home_derp,
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
    // This is the one place an unauthenticated peer can add a pending entry,
    // so it is always accounted: a request without a resolvable peer address
    // shares the `Unknown` bucket instead of being exempt.
    state.registration_cache.insert_from_source(
        registration_id.clone(),
        record,
        Some(requested_hostinfo),
        Some(source.unwrap_or(RegistrationSource::Unknown)),
    );

    register_json_response(&RegisterResponse {
        user: empty_simple_user(),
        login: empty_simple_login(),
        node_key_expired: false,
        auth_url: auth_url_for_registration(&state, &registration_id),
        machine_authorized: false,
        error: String::new(),
        node_key_signature: None,
    })
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
        .map(|h| {
            h.routable_ips
                .iter()
                .map(|route| {
                    if route.is_empty() {
                        Ok(String::new())
                    } else {
                        headscale_api_acl::go_netip::parse_prefix_text(route)
                    }
                })
                .collect::<Result<Vec<_>, _>>()
        })
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
        .map(|hostinfo| hostinfo.request_tags.clone())
        .unwrap_or_default()
}

fn invalid_requested_tags_response(tags: &[String]) -> axum::response::Response {
    register_error_response(format!(
        "handling register with auth key: creating new node: requested tags [{}] are invalid or not permitted",
        tags.join(" "),
    ))
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
) -> Option<chrono::DateTime<chrono::Utc>> {
    expiry
        .filter(|expiry| !is_go_zero_expiry(*expiry))
        .or(default_expiry)
}

fn is_go_zero_expiry(expiry: chrono::DateTime<chrono::Utc>) -> bool {
    expiry
        == chrono::NaiveDate::from_ymd_opt(1, 1, 1)
            .expect("valid Go zero date")
            .and_hms_opt(0, 0, 0)
            .expect("valid Go zero time")
            .and_utc()
}

fn preauth_error_response(
    error: impl Into<super::RegistrationRedeemError>,
) -> axum::response::Response {
    register_error_response(error.into().message)
}

fn existing_node_can_refresh_with_key(
    existing: &MachineRecord,
    key: &super::RedeemOk,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let tagged = !existing.forced_tags.is_empty();
    if !tagged && existing.is_expired_at(now) {
        return false;
    }
    if !key.tags.is_empty() {
        return tagged && existing.auth_key_id.is_some() && existing.auth_key_id == key.auth_key_id;
    }
    true
}

async fn logout_existing_node(
    state: &WireState,
    node_key_hex: &str,
    original: &MachineRecord,
    expiry: chrono::DateTime<chrono::Utc>,
) -> axum::response::Response {
    let registration_guard = state
        .machines
        .lock_registration(&original.machine_key_hex)
        .await;
    let Some(record) = state.machines.get(node_key_hex) else {
        return register_json_response(&node_key_expired_response(false));
    };
    if let Err(response) = validate_existing_machine_key(
        &original.machine_key_hex,
        &record,
        REGISTER_LOGOUT_MACHINE_KEY_MISMATCH,
    ) {
        return response;
    }
    let now = chrono::Utc::now();
    if record.is_expired_at(now) {
        return register_json_response(&node_key_expired_response(false));
    }
    // Tagged logout does not override a deliberate admin expiry. Ephemeral
    // nodes are removed even when tagged, following Go's branch ordering.
    if record.is_tagged() && !record.ephemeral {
        return register_json_response(&register_response_for_live_record(
            &state.machines,
            &record,
        ));
    }
    let state = state.clone();
    let node_key_hex = node_key_hex.to_owned();
    super::complete_state_mutation(async move {
        let _registration = registration_guard;
        let expiry = expiry.max(chrono::Utc::now());
        if record.ephemeral {
            if let Some(store) = &state.registration_store {
                let saved = if store.supports_guarded_ephemeral_deletion() {
                    store.delete_ephemeral_registration(&record).await
                } else {
                    store.persist_wire_logout(&record, expiry).await
                };
                if let Err(error) = saved {
                    return register_error_response(format!(
                        "handling logout: deleting ephemeral node: {error}"
                    ));
                }
            }
            if let Err(error) = state.machines.try_delete(&node_key_hex) {
                // The explicit removal is already dispatched if policy
                // refresh fails after the durable deletion.
                return register_error_response(format!(
                    "handling logout: deleting ephemeral node: {error}"
                ));
            }
            return register_json_response(&node_key_expired_response(false));
        }
        let node_id = record.stable_node_id_for_key(&node_key_hex);
        let Some((updated, online_changed)) =
            state.machines.set_node_expiry_quiet(node_id, Some(expiry))
        else {
            return register_error_response(format!(
                "handling logout: setting node expiry: node no longer exists in NodeStore: {node_id}"
            ));
        };
        if let Some(store) = &state.registration_store
            && let Err(error) = store.persist_wire_logout(&updated, expiry).await
        {
            return register_error_response(format!("handling logout: setting node expiry: {error}"));
        }
        let policy_changed = match state.machines.try_refresh_policy_node_inputs() {
            Ok(changed) => changed == Some(true),
            Err(error) => return register_error_response(format!(
                "handling logout: setting node expiry: updating policy manager after setting expiry: {error}"
            )),
        };
        state.machines.wake_node_expiry_change(node_id, policy_changed, online_changed);
        register_json_response(&register_response_for_live_record(&state.machines, &updated))
    })
    .await
    .unwrap_or_else(|error| register_error_response(format!("finishing node logout: {error}")))
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
    (
        status,
        [(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
        format!("{message}\n"),
    )
        .into_response()
}

fn register_json_response(response: &RegisterResponse) -> axum::response::Response {
    let mut body = match super::register_json::encode(response) {
        Ok(body) => body,
        Err(error) => {
            // Go writes its 200 response headers before Encoder.Encode.
            tracing::error!(%error, "failed to encode RegisterResponse");
            return (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )],
                Vec::<u8>::new(),
            )
                .into_response();
        }
    };
    body.push(b'\n');
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

fn register_error_response(error: impl Into<String>) -> axum::response::Response {
    register_json_response(&RegisterResponse {
        user: empty_simple_user(),
        login: empty_simple_login(),
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: false,
        error: error.into(),
        node_key_signature: None,
    })
}

fn allocate_register_ips(
    state: &WireState,
    alloc_input: &str,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), axum::response::Response> {
    super::allocate_registration_addresses(state.ip_allocator.as_ref(), alloc_input).map_err(
        |error| {
            register_error_response(format!(
                "handling register with auth key: creating new node: {error}"
            ))
        },
    )
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

fn register_response_for_live_record(
    registry: &super::MachineRegistry,
    record: &MachineRecord,
) -> RegisterResponse {
    let response = register_response_for_record(record);
    if record.is_tagged() {
        return response;
    }
    #[cfg(feature = "admin")]
    let mut response = response;
    #[cfg(feature = "admin")]
    match registry.cached_native_user(record) {
        Some(None) => {
            response.user = empty_simple_user();
            response.login = empty_simple_login();
        }
        Some(Some(user)) => {
            let login_name = if !user.email.is_empty() {
                user.email.clone()
            } else if !user.name.is_empty() {
                user.name.clone()
            } else if !user.provider_id.is_empty() {
                user.provider_id.clone()
            } else {
                user.id.to_string()
            };
            let display_name = if user.display_name.is_empty() {
                login_name.clone()
            } else {
                user.display_name
            };
            response.user = SimpleUser {
                id: user.id,
                display_name: display_name.clone(),
                profile_pic_url: user.profile_pic_url.clone(),
                created: user.created_at_precise.or_else(|| {
                    i64::try_from(user.created_at)
                        .ok()
                        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
                }),
            };
            response.login = SimpleLogin {
                id: user.id,
                provider: user.provider,
                login_name,
                display_name,
                profile_pic_url: user.profile_pic_url,
            };
        }
        None => {}
    }
    #[cfg(not(feature = "admin"))]
    let _ = registry;
    response
}

fn register_response_for_record(record: &MachineRecord) -> RegisterResponse {
    let profile = record.tailscale_user_profile();
    RegisterResponse {
        user: SimpleUser {
            id: profile.id,
            display_name: profile.display_name.clone(),
            profile_pic_url: profile.profile_pic_url.clone(),
            created: if record.is_tagged() {
                None
            } else {
                record.user_created_at
            },
        },
        login: SimpleLogin {
            id: profile.id,
            provider: if record.is_tagged() {
                String::new()
            } else {
                record.user_provider.clone()
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

fn registration_id_from_followup(followup: &str) -> Result<Option<String>, &'static str> {
    let path = crate::go_url::Url::parse(followup).map_err(|_| "invalid followup URL")?;
    // strings.ReplaceAll removes every occurrence from decoded URL.Path.
    let mut id = Vec::new();
    let mut rest = path.path();
    const MARKER: &[u8] = b"/register/";
    while let Some(at) = rest.windows(MARKER.len()).position(|part| part == MARKER) {
        id.extend_from_slice(&rest[..at]);
        rest = &rest[at + MARKER.len()..];
    }
    id.extend_from_slice(rest);
    if id.len() != AUTH_ID_LENGTH || !id.starts_with(AUTH_ID_PREFIX.as_bytes()) {
        return Err("invalid registration ID");
    }
    // AuthIDs are only shape-validated by Go. Preserve a non-UTF-8 ID as
    // an explicit cache miss, never a lossy or sentinel lookup key.
    Ok(std::str::from_utf8(&id[AUTH_ID_PREFIX.len()..])
        .ok()
        .map(str::to_owned))
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
        key_expiry: rec.expiry.filter(|expiry| !is_go_zero_expiry(*expiry)),
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
        disco_key: rec
            .disco_key
            .as_ref()
            .filter(|key| !key.is_empty() && key.as_str() != ZERO_DISCO_KEY)
            .cloned(),
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
    use crate::tailscale_wire::RegistrationGate;
    use crate::tailscale_wire::{
        AllocError, IpAllocator, MachineRegistrationStore, MachineRegistry,
        PersistedMachineRegistration, PreauthRedeemer, RedeemOk, WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        router_with_oidc,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use async_trait::async_trait;
    use axum::body::to_bytes;
    use std::collections::BTreeMap;
    use std::{sync::Arc, time::Duration};
    use tempfile::tempdir;
    use tower::ServiceExt;

    const TEST_MACHINE_KEY_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn register_response_uses_owner_metadata_and_serializes_null_signature() {
        let created_at = chrono::Utc::now();
        let mut record = MachineRecord::new_at_with_addresses(
            created_at,
            "ab".repeat(32),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".to_string(),
            "alice-node".to_string(),
            Some(Ipv4Addr::new(100, 64, 0, 1)),
            None,
            false,
        );
        record.set_user_identity(Some(7), "alice".into(), "Alice".into(), String::new());
        record.set_user_account_metadata("google".into(), Some(created_at));
        record.register_method = 1;

        let response = serde_json::to_value(register_response_for_record(&record)).unwrap();
        assert_eq!(response["User"]["ID"], 7);
        let serialized_created = response["User"]["Created"].as_str().unwrap();
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(serialized_created).unwrap(),
            created_at
        );
        assert_eq!(response["Login"]["Provider"], "google");
        assert!(response.get("NodeKeySignature").is_some());
        assert!(response["NodeKeySignature"].is_null());
    }

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
            registration_gate: None,
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

    /// Test double for [`RegistrationGate`]: records what it was asked
    /// about and answers with a fixed verdict.
    #[derive(Default)]
    struct GateFixture {
        refusal: Option<String>,
        seen: parking_lot::Mutex<Vec<(String, String, Option<String>)>>,
    }

    impl GateFixture {
        fn admit() -> Self {
            Self::default()
        }

        fn refuse(reason: &str) -> Self {
            Self {
                refusal: Some(reason.to_string()),
                seen: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<(String, String, Option<String>)> {
            self.seen.lock().clone()
        }
    }

    #[async_trait]
    impl RegistrationGate for GateFixture {
        async fn admit(&self, req: RegistrationAdmission<'_>) -> Result<(), String> {
            self.seen.lock().push((
                req.node_key_hex.to_string(),
                req.machine_key_hex.to_string(),
                req.hostname.map(str::to_string),
            ));
            match &self.refusal {
                Some(reason) => Err(reason.clone()),
                None => Ok(()),
            }
        }
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
            registration_id_from_followup(&format!("/register/{auth_id}"))
                .unwrap()
                .unwrap(),
            id
        );
        assert_eq!(
            registration_id_from_followup(&format!("https://headscale.example/register/{auth_id}"))
                .unwrap()
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

    /// A refused key gets no record, keeps its preauth key unspent, and the
    /// client is told why (stock `tailscale up` prints `RegisterResponse.error`).
    #[tokio::test]
    async fn register_gate_refusal_leaves_no_record_and_returns_the_reason() {
        let (mut state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-gate-refused";
        redeemer.insert(authkey, "alice");
        state.registration_gate = Some(Arc::new(GateFixture::refuse(
            "node key is not in the anchored member set",
        )));
        let app = router(state.clone());
        let node_key_hex = "c1".repeat(32);

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
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            body["Error"], "node key is not in the anchored member set",
            "{body}"
        );
        assert_eq!(body["MachineAuthorized"], serde_json::json!(false));
        assert!(
            state.machines.get(&node_key_hex).is_none(),
            "a refused key must not land in the registry"
        );
        assert!(
            redeemer.contains(authkey),
            "the gate runs before redemption, so the key is still spendable"
        );
    }

    /// The gate sees the key pair and the reported hostname, and an admitting
    /// gate changes nothing about a normal registration.
    #[tokio::test]
    async fn register_gate_sees_keys_and_admits_unchanged() {
        let (mut state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-gate-admitted";
        redeemer.insert(authkey, "alice");
        let gate = Arc::new(GateFixture::admit());
        state.registration_gate = Some(gate.clone());
        let app = router(state.clone());
        let node_key_hex = "c2".repeat(32);

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
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(body["Error"], "", "{body}");
        assert_eq!(body["MachineAuthorized"], serde_json::json!(true));
        assert!(state.machines.get(&node_key_hex).is_some());
        assert_eq!(
            gate.seen(),
            vec![(
                node_key_hex.clone(),
                TEST_MACHINE_KEY_HEX.to_string(),
                Some("peer-a".to_string())
            )]
        );
    }

    /// A logout-shaped request for a key the control plane has no record of
    /// — the operator already deleted it — is exempt too, so `tailscale
    /// logout` does not error. An auth key in the same request makes it a
    /// registration attempt again, and that is gated.
    #[tokio::test]
    async fn register_gate_exempts_recordless_logout_but_not_a_logout_shaped_registration() {
        let (mut state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-gate-expired";
        redeemer.insert(authkey, "alice");
        state.registration_gate = Some(Arc::new(GateFixture::refuse("not a member")));
        let node_key_hex = "c4".repeat(32);

        // No record, expiry in the past, no auth key ⇒ not gated.
        let mut body = req_body(&node_key_hex, "");
        body["Auth"] = serde_json::Value::Null;
        body["Expiry"] = serde_json::json!("2000-01-01T00:00:00Z");
        let resp = router(state.clone())
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
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_ne!(
            parsed["Error"], "not a member",
            "a record-less logout must not be refused by the gate: {parsed}"
        );
        assert!(state.machines.get(&node_key_hex).is_none());

        // Same shape, but with an auth key: a registration attempt, gated.
        let mut body = req_body(&node_key_hex, authkey);
        body["Expiry"] = serde_json::json!("2000-01-01T00:00:00Z");
        let resp = router(state.clone())
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
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["Error"], "not a member", "{parsed}");
        assert!(state.machines.get(&node_key_hex).is_none());
        assert!(redeemer.contains(authkey), "the key was not spent");
    }

    /// Logging out is exempt: a node whose admission was revoked can still
    /// complete the deregistration it started.
    #[tokio::test]
    async fn register_gate_does_not_block_logout() {
        let (mut state, redeemer, _dir) = fixture();
        let authkey = "hskey-auth-gate-logout";
        redeemer.insert(authkey, "alice");
        let node_key_hex = "c3".repeat(32);
        let app = router(state.clone());
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
        assert!(state.machines.get(&node_key_hex).is_some());

        // Admission revoked after the node registered.
        state.registration_gate = Some(Arc::new(GateFixture::refuse("evicted")));
        let mut body = req_body(&node_key_hex, "");
        body["Auth"] = serde_json::Value::Null;
        body["Expiry"] = serde_json::json!("2000-01-01T00:00:00Z");
        let app = router(state.clone());
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
        let parsed: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(parsed["Error"], "", "logout must not be gated: {parsed}");
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
        // headscale-go v0.29.5 HandleNodeFromPreAuthKey re-registration sets
        // node.Hostname (raw) and keeps node.GivenName.
        assert_eq!(rotated.hostname, "peer-a");
        assert_eq!(rotated.raw_hostname, "peer-rotated");
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
        assert_eq!(raw.hostname, "peer-rotated");
        assert_eq!(raw.given_name, "peer-a");
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
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            ev["Error"],
            "handling register with auth key: creating new node: requested tags [tag:server tag:server tag:db] are invalid or not permitted"
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
        // headscale-go v0.29.5 HandleNodeFromPreAuthKey re-registration sets
        // node.Hostname (raw) and keeps node.GivenName.
        assert_eq!(rotated.hostname, "peer-a");
        assert_eq!(rotated.raw_hostname, "peer-rotated");
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
    async fn authkey_register_same_machine_tagged_key_converts_user_node_in_place() {
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
        let first = state.machines.get(&first_node_key).unwrap();

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

        assert_eq!(state.machines.len(), 1);
        assert!(state.machines.get(&first_node_key).is_none());
        let tagged = state.machines.get(&tagged_node_key).unwrap();
        assert!(tagged.user.is_empty());
        assert_eq!(tagged.forced_tags, vec!["tag:server"]);
        assert_eq!(tagged.ipv4, first.ipv4);
        assert!(!redeemer.contains(tagged_authkey));
    }

    #[tokio::test]
    async fn tagged_reauth_same_key_keeps_admin_tags_but_new_key_retags_in_place() {
        let (state, redeemer, _dir) = fixture();
        let first_key = "hskey-auth-tagged-retag-first";
        let second_key = "hskey-auth-tagged-retag-second";
        redeemer.insert_full(
            first_key,
            RedeemOk::for_user("alice")
                .tags(vec!["tag:server".into()])
                .auth_key_id(101),
        );
        redeemer.insert_full(
            second_key,
            RedeemOk::for_user("alice")
                .tags(vec!["tag:database".into()])
                .auth_key_id(102),
        );
        let app = router(state.clone());
        let first_node_key = "8a".repeat(32);
        let second_node_key = "8b".repeat(32);
        let machine_key = "c8".repeat(32);

        for (step, (node_key, auth_key)) in [
            (&first_node_key, first_key),
            (&first_node_key, first_key),
            (&second_node_key, second_key),
        ]
        .into_iter()
        .enumerate()
        {
            if auth_key == first_key && state.machines.get(&first_node_key).is_some() {
                let mut admin_override = state.machines.get(&first_node_key).unwrap();
                admin_override.forced_tags = vec!["tag:manual".into()];
                admin_override.expiry = Some(chrono::Utc::now() + chrono::Duration::hours(1));
                state
                    .machines
                    .upsert(first_node_key.clone(), admin_override);
            }
            let mut req = axum::http::Request::builder()
                .method("POST")
                .uri(format!("/machine/nodekey:{node_key}/register"))
                .body(axum::body::Body::from(
                    serde_json::to_vec(&req_body(node_key, auth_key)).unwrap(),
                ))
                .unwrap();
            req.extensions_mut()
                .insert(NoisePeerMachineKey(machine_key.clone()));
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{auth_key}");
            if step == 1 {
                let unchanged = state.machines.get(&first_node_key).unwrap();
                assert_eq!(unchanged.forced_tags, vec!["tag:manual"]);
                assert_eq!(unchanged.auth_key_id, Some(101));
                assert!(
                    unchanged
                        .expiry
                        .is_some_and(|expiry| expiry > chrono::Utc::now())
                );
            }
        }

        assert_eq!(state.machines.len(), 1);
        assert!(state.machines.get(&first_node_key).is_none());
        let retagged = state.machines.get(&second_node_key).unwrap();
        assert_eq!(retagged.forced_tags, vec!["tag:database"]);
        assert_eq!(retagged.auth_key_id, Some(102));
        assert!(
            retagged
                .expiry
                .is_some_and(|expiry| expiry > chrono::Utc::now())
        );
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
        // headscale-go v0.29.5: HandleNodeFromPreAuthKey's in-place update
        // rejects a NodeKey bound to another machine with ErrNodeKeyInUse
        // ("node key already in use by another machine"); handleRegister wraps
        // it as "handling register with auth key: %w" and RegistrationHandler
        // always answers 200 with RegisterResponse.Error (regErr).
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            rr.error,
            "handling register with auth key: node key already in use by another machine"
        );
        assert!(!rr.machine_authorized);
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
        // Re-registration updates the raw Hostname but keeps GivenName (Go
        // HandleNodeFromPreAuthKey).
        let restarted = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(restarted.hostname, "peer-a");
        assert_eq!(restarted.raw_hostname, "peer-restarted");
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
        assert_eq!(rr.error, "authkey already used");
        assert_eq!(state.machines.len(), 1);
    }

    #[tokio::test]
    async fn authkey_used_key_reregister_accepts_another_key_for_the_same_user() {
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
        assert!(rr.machine_authorized);
        let refreshed = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(refreshed.auth_key_id, Some(202));
        // Re-registration updates the raw Hostname but keeps GivenName (Go
        // HandleNodeFromPreAuthKey).
        assert_eq!(refreshed.hostname, "peer-a");
        assert_eq!(refreshed.raw_hostname, "wrong-used-key");

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
        assert_eq!(reauthed.hostname, "peer-a");
        assert_eq!(reauthed.raw_hostname, "original-used-key");
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
        // Re-registration updates the raw Hostname but keeps GivenName (Go
        // HandleNodeFromPreAuthKey).
        let restarted = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(restarted.hostname, "peer-a");
        assert_eq!(restarted.raw_hostname, "peer-expired-restart");

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
        assert_eq!(rr.error, "authkey expired");
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
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(ev["Error"], "extending key is not allowed");
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

        // headscale-go handleRegisterWithAuthKey runs State.AutoApproveRoutes
        // right after HandleNodeFromPreAuthKey; SetApprovedRoutes' change is
        // a change.PolicyChange() sent after the registration change.
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.available_routes, vec!["10.30.1.0/24", "10.99.0.0/24"]);
        assert_eq!(rec.approved_routes, vec!["10.30.1.0/24"]);
        let changes = state.machines.map_change_history();
        let last = changes.last().expect("registration records map changes");
        assert_eq!(last.reason_labels(), vec!["policy change"]);
        assert!(last.content.include_policy);
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
        // The mock redeemer reports an unknown key (RedeemError::Unknown), i.e.
        // headscale-go's GetPreAuthKey -> ErrPreAuthKeyNotFound (wraps
        // gorm.ErrRecordNotFound), which handleRegisterWithAuthKey maps to
        // HTTPError(401, "invalid pre auth key"); RegistrationHandler returns
        // it as RegisterResponse.Error with HTTP 200.
        assert_eq!(rr.error, "invalid pre auth key");
        assert!(!rr.machine_authorized);
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
    async fn completed_followup_requires_the_registered_machine_key() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        let node_key_hex = "c1".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "followup-machine-binding" },
        });
        let resp = router(state.clone())
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
        let pending_response: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let registration_id = pending_response
            .auth_url
            .strip_prefix("https://headscale.example/register/hskey-authreq-")
            .unwrap()
            .to_string();
        let mut registered = state.registration_cache.get(&registration_id).unwrap();
        registered.user = "alice".into();
        registered.user_id = Some(42);

        let followup_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Followup": pending_response.auth_url,
            "Hostinfo": { "Hostname": "followup-machine-binding" },
        });
        let attacker_node_key_hex = "c2".repeat(32);
        let mut attacker_body = followup_body.clone();
        attacker_body["NodeKey"] = serde_json::json!(format!("nodekey:{attacker_node_key_hex}"));
        let cancellation = NoiseRequestCancellation::new();
        let rightful = {
            let state = state.clone();
            let node_key_hex = node_key_hex.clone();
            let body: RegisterRequest = serde_json::from_value(followup_body.clone()).unwrap();
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                register_inner(
                    state,
                    node_key_hex,
                    TEST_MACHINE_KEY_HEX.to_string(),
                    body,
                    Some(cancellation),
                )
                .await
            })
        };
        let attacker = {
            let state = state.clone();
            let body: RegisterRequest = serde_json::from_value(attacker_body).unwrap();
            tokio::spawn(async move {
                register_inner(state, attacker_node_key_hex, "11".repeat(32), body, None).await
            })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            state
                .registration_cache
                .complete(&registration_id, registered)
        );
        cancellation.cancel();

        let rightful = tokio::time::timeout(Duration::from_secs(1), rightful)
            .await
            .unwrap()
            .unwrap();
        let attacker = tokio::time::timeout(Duration::from_secs(1), attacker)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rightful.status(), StatusCode::OK);
        assert_eq!(attacker.status(), StatusCode::OK);
        let rightful: RegisterResponse =
            serde_json::from_slice(&to_bytes(rightful.into_body(), 8192).await.unwrap()).unwrap();
        let attacker: RegisterResponse =
            serde_json::from_slice(&to_bytes(attacker.into_body(), 8192).await.unwrap()).unwrap();
        assert!(rightful.machine_authorized);
        assert_eq!(rightful.user.id, 42);
        assert!(!attacker.machine_authorized);
        assert_eq!(attacker.user.id, 0);
        assert_eq!(attacker.error, REGISTER_EXISTING_NODE_MACHINE_KEY_MISMATCH);
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
    async fn missing_authkey_interactive_registration_does_not_apply_node_expiry_default() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let app = router(state.clone());
        let node_key_hex = "d4".repeat(32);
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
        assert!(
            pending.expiry.is_none(),
            "only client-requested expiry is cached"
        );
    }

    #[tokio::test]
    async fn missing_authkey_interactive_registration_preserves_client_expiry() {
        let (mut state, _redeemer, _dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        state.runtime_config = Arc::new(runtime_config_with_node_expiry(Duration::from_secs(3600)));
        let node_key_hex = "d5".repeat(32);
        let requested_expiry = chrono::Utc::now() + chrono::Duration::hours(2);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending-requested-expiry" },
            "Expiry": requested_expiry,
        });
        let resp = router(state.clone())
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
        let response: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let registration_id = response
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .and_then(|id| id.strip_prefix(AUTH_ID_PREFIX))
            .unwrap();
        let pending = state.registration_cache.get(registration_id).unwrap();
        assert_eq!(pending.expiry, Some(requested_expiry));
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
        assert_eq!(rr.error, "invalid pre auth key");
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

    /// Register `node_key_hex` interactively (no auth key) as if it arrived
    /// on a Noise connection from `source`, returning the pending
    /// registration ID the response hands out.
    async fn register_interactive_from(
        state: &WireState,
        node_key_hex: String,
        source: Option<&str>,
        followup: Option<&str>,
    ) -> (RegisterResponse, String) {
        let mut body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "flood" },
        });
        if let Some(followup) = followup {
            body["Followup"] = serde_json::json!(followup);
        }
        let body: RegisterRequest = serde_json::from_value(body).unwrap();
        let resp = register_inner_from(
            state.clone(),
            node_key_hex,
            TEST_MACHINE_KEY_HEX.to_string(),
            body,
            None,
            source.map(|text| RegistrationSource::from_remote_addr(text).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let response: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        let registration_id = response
            .auth_url
            .rsplit_once(AUTH_ID_PREFIX)
            .map(|(_, id)| id.to_owned())
            .expect("pending registration hands out an auth URL");
        (response, registration_id)
    }

    fn flood_state() -> (WireState, tempfile::TempDir) {
        let (mut state, _redeemer, dir) = fixture();
        state.public_control_url = Some("https://headscale.example".into());
        (state, dir)
    }

    /// F-REGCACHE: the attack as first reproduced (an unauthenticated peer's
    /// Register flood evicted an admin's pending approval from the default
    /// 1024-entry cache) must now only cost the flooding source its own
    /// entries.
    #[tokio::test]
    async fn unauthenticated_register_flood_cannot_evict_another_sources_pending_approval() {
        let (state, _dir) = flood_state();
        let cache = state.registration_cache.clone();
        let max_entries = cache.max_entries();
        assert_eq!(max_entries, 1024);

        let (_, victim) = register_interactive_from(
            &state,
            format!("{:064x}", 0),
            Some("203.0.113.7:4000"),
            None,
        )
        .await;
        assert!(cache.get_pending_registration(&victim).is_some());

        let flooder = RegistrationSource::from_remote_addr("198.51.100.9:1").unwrap();
        for i in 1..=max_entries {
            // A fresh ephemeral port each time: the port is not the source.
            let (response, _) = register_interactive_from(
                &state,
                format!("{i:064x}"),
                Some(&format!("198.51.100.9:{}", 1024 + i)),
                None,
            )
            .await;
            assert!(!response.machine_authorized, "the flooder is still served");
        }

        assert!(
            cache.get_pending_registration(&victim).is_some(),
            "the flood must not push the earlier pending entry out"
        );
        assert_eq!(
            cache.pending_from_source(flooder),
            crate::tailscale_wire::REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
        assert_eq!(
            cache.len(),
            1 + crate::tailscale_wire::REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
    }

    /// A request with no resolvable peer address is not an exemption: all of
    /// them share one bucket.
    #[tokio::test]
    async fn register_flood_without_a_peer_address_shares_the_unknown_source() {
        let (state, _dir) = flood_state();
        let cache = state.registration_cache.clone();
        let (_, victim) = register_interactive_from(
            &state,
            format!("{:064x}", 0),
            Some("203.0.113.7:4000"),
            None,
        )
        .await;

        for i in 1..=cache.max_entries() {
            register_interactive_from(&state, format!("{i:064x}"), None, None).await;
        }

        assert!(cache.get_pending_registration(&victim).is_some());
        assert_eq!(
            cache.pending_from_source(RegistrationSource::Unknown),
            crate::tailscale_wire::REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
    }

    /// What a source over its quota experiences: every Register still gets the
    /// normal pending response, only its own oldest entries are dropped, and a
    /// followup for a dropped entry restarts registration with a fresh auth URL
    /// exactly like Go's `reqToNewRegisterResponse` for an expired entry.
    #[tokio::test]
    async fn source_over_quota_keeps_working_and_only_loses_its_own_oldest_entries() {
        let (mut state, _dir) = flood_state();
        state.registration_cache = Arc::new(
            crate::tailscale_wire::RegistrationCache::with_tuning_and_max_entries(
                Duration::from_secs(60),
                Duration::from_secs(120),
                100,
            )
            .with_max_pending_per_source(3),
        );
        let cache = state.registration_cache.clone();
        let busy = "198.51.100.9:5000";
        let busy_source = RegistrationSource::from_remote_addr(busy).unwrap();

        let (_, bystander) =
            register_interactive_from(&state, "b0".repeat(32), Some("203.0.113.7:1"), None).await;
        let mut ids = Vec::new();
        let mut urls = Vec::new();
        for i in 0..5_u8 {
            let (response, id) =
                register_interactive_from(&state, format!("{i:02x}").repeat(32), Some(busy), None)
                    .await;
            assert!(!response.machine_authorized);
            assert!(response.error.is_empty());
            urls.push(response.auth_url);
            ids.push(id);
        }

        assert_eq!(cache.pending_from_source(busy_source), 3);
        assert!(cache.get_pending_registration(&ids[0]).is_none());
        assert!(cache.get_pending_registration(&ids[1]).is_none());
        for id in &ids[2..] {
            assert!(cache.get_pending_registration(id).is_some());
        }
        assert!(cache.get_pending_registration(&bystander).is_some());

        // The dropped entry's client polls its followup: it is told to start
        // over, and the restart is accounted to the same source again.
        let (restarted, restarted_id) =
            register_interactive_from(&state, "00".repeat(32), Some(busy), Some(&urls[0])).await;
        assert!(!restarted.machine_authorized);
        assert_ne!(restarted.auth_url, urls[0]);
        assert_eq!(cache.pending_from_source(busy_source), 3);
        assert!(cache.get_pending_registration(&restarted_id).is_some());
        assert!(cache.get_pending_registration(&bystander).is_some());

        // A surviving entry still completes normally.
        let mut registered = cache.get(&ids[4]).unwrap();
        registered.user = "alice".into();
        assert!(cache.complete(&ids[4], registered));
        assert_eq!(cache.pending_from_source(busy_source), 2);
    }
}
