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
//!   `{"error": "..."}` body for 4xx. The HTTP status is 400 for
//!   malformed input and 401 for an unknown / expired preauth key.
//!   Upstream uses 401 for "no authorization", which we mirror.
//! - **User ID derivation:** the upstream uses a database primary
//!   key. We don't have a DB, so we FNV-hash the user label. This is
//!   stable across requests for the same user but doesn't survive a
//!   user-label rename.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
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

use super::wire::{
    stable_id_from_key, strip_key_prefix, HostInfo, MapNode, RegisterRequest, RegisterResponse,
    SimpleLogin, SimpleUser,
};
use super::{MachineRecord, RedeemError, WireState};

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub async fn handle_register(
    State(state): State<WireState>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> axum::response::Response {
    let body = match parse_register_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
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
    register_inner(state, body_node_key_hex, body).await
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
    raw: Bytes,
) -> axum::response::Response {
    let body = match parse_register_body(&raw) {
        Ok(b) => b,
        Err(resp) => return resp,
    };
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
    register_inner(state, body_node_key_hex, body).await
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
    body: RegisterRequest,
) -> axum::response::Response {
    // Redeem the presented preauth token. Absence of an `Auth.AuthKey`
    // is treated as "no authkey presented" which is a 401.
    let authkey = body
        .auth
        .as_ref()
        .map_or("", |a| a.auth_key.as_str());
    if authkey.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "no preauth key presented".into(),
            }),
        )
            .into_response();
    }

    let user = match state.preauth.redeem(authkey).await {
        Ok(u) => u,
        Err(RedeemError::Unknown) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "preauth key not recognised".into(),
                }),
            )
                .into_response();
        }
        Err(RedeemError::Expired) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: "preauth key expired".into(),
                }),
            )
                .into_response();
        }
    };

    // Allocate a tailnet IPv4. The allocator is deterministic given
    // the user label, so a repeated register with the same user keeps
    // the same IP — handy for tests, but the `MachineRegistry` itself
    // keys on the node key so duplicate registers under different
    // node keys do get separate records.
    let alloc_input = format!("{user}:{node_key_hex}");
    let ipv4: Ipv4Addr = match state.ip_allocator.allocate(&alloc_input) {
        Ok(ip) => ip,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: format!("ip allocation failed: {e}"),
                }),
            )
                .into_response();
        }
    };

    let hostname = body
        .hostinfo
        .as_ref()
        .map(|h| h.hostname.clone())
        .unwrap_or_default();
    let rec = MachineRecord {
        node_key_hex: node_key_hex.clone(),
        machine_key_hex: String::new(),
        user: user.clone(),
        hostname,
        ipv4,
    };
    state.machines.upsert(node_key_hex, rec);

    let user_id = stable_id_from_key(&user);
    let resp = RegisterResponse {
        user: SimpleUser {
            id: user_id,
            login_name: user.clone(),
            display_name: user.clone(),
        },
        login: SimpleLogin {
            id: user_id,
            provider: "octravpn-preauth".into(),
            login_name: user.clone(),
            display_name: user,
        },
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: true,
    };
    Json(resp).into_response()
}

/// Helper exposed for tests + `/map`: turn a `MachineRecord` into the
/// `MapNode` shape we ship in `MapResponse.Peers`.
pub fn record_to_map_node(rec: &MachineRecord, domain: &str) -> MapNode {
    let name = if rec.hostname.is_empty() {
        format!("node-{}.{}", &rec.node_key_hex[..8.min(rec.node_key_hex.len())], domain)
    } else {
        format!("{}.{}", rec.hostname, domain)
    };
    MapNode {
        id: stable_id_from_key(&rec.node_key_hex),
        key: format!("nodekey:{}", rec.node_key_hex),
        machine: format!("mkey:{}", rec.machine_key_hex),
        addresses: vec![format!("{}/32", rec.ipv4)],
        allowed_ips: vec![format!("{}/32", rec.ipv4)],
        hostinfo: HostInfo {
            hostname: rec.hostname.clone(),
            os: String::new(),
            os_version: String::new(),
        },
        name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        noise::ServerNoiseKey,
        router,
        test_support::{MockIpAllocator, MockRedeemer},
        MachineRegistry, WireState,
    };
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture() -> (WireState, MockRedeemer, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let redeemer = MockRedeemer::new();
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(redeemer.clone()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
        };
        (state, redeemer, dir)
    }

    fn req_body(node_key_hex: &str, authkey: &str) -> serde_json::Value {
        serde_json::json!({
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Auth": { "AuthKey": authkey },
            "Hostinfo": { "Hostname": "peer-a", "OS": "linux", "OSVersion": "6.6" },
        })
    }

    #[tokio::test]
    async fn happy_path_redeems_key() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "octrapreauth-alice-test-key";
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
        let rr: RegisterResponse = serde_json::from_slice(&raw).unwrap();
        assert!(rr.machine_authorized);
        assert_eq!(rr.user.login_name, "alice");
        // Mock redeemer is single-use — second redeem fails.
        assert!(!redeemer.contains(authkey));
        // Machine registry remembers the registration.
        assert_eq!(state.machines.len(), 1);
        let rec = state.machines.get(&node_key_hex).unwrap();
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.hostname, "peer-a");
        // Allocated IP is in CGNAT.
        assert!(rec.ipv4.octets()[0] == 100);
    }

    #[tokio::test]
    async fn rejects_unknown_authkey() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let node_key_hex = "bb".repeat(32);
        let body = req_body(&node_key_hex, "octrapreauth-deadbeef");
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
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        let ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(ev["error"].as_str().unwrap().contains("not recognised"));
    }

    #[tokio::test]
    async fn rejects_missing_authkey() {
        let (state, _redeemer, _dir) = fixture();
        let app = router(state);
        let node_key_hex = "cc".repeat(32);
        let body = serde_json::json!({
            "NodeKey": format!("nodekey:{node_key_hex}"),
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Flat v1.78+ path: NodeKey lives in the body, not the URL.
    #[tokio::test]
    async fn flat_register_extracts_node_key_from_body() {
        let (state, redeemer, _dir) = fixture();
        let authkey = "octrapreauth-flat-alice";
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
        assert_eq!(rr.user.login_name, "alice");
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
        let authkey = "octrapreauth-keyed-regression";
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
        let authkey = "octrapreauth-mismatch-test";
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
