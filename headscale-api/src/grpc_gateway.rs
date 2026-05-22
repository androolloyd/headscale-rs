//! grpc-gateway-compatible HTTP routes for upstream `HeadscaleService`.
//!
//! Headscale-go mounts `/api/v1/*` by running `grpc-gateway` in front of
//! the real gRPC service. This module mirrors that split for
//! replacement-mode deployments: handlers decode the upstream HTTP
//! annotations, call [`crate::grpc::upstream::HeadscaleAdminService`],
//! then render protojson-style JSON.

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, RawQuery, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tonic::{Code, Request as TonicRequest, Status, metadata::MetadataMap};

use crate::generated::headscale_service_server::HeadscaleService;
use crate::generated::{
    ApiKey, BackfillNodeIPsRequest, CheckPolicyRequest, CreateApiKeyRequest,
    CreatePreAuthKeyRequest, CreateUserRequest, DebugCreateNodeRequest, DeleteApiKeyRequest,
    DeleteNodeRequest, DeletePreAuthKeyRequest, DeleteUserRequest, ExpireApiKeyRequest,
    ExpireNodeRequest, ExpirePreAuthKeyRequest, GetNodeRequest, GetPolicyRequest, HealthRequest,
    ListApiKeysRequest, ListNodesRequest, ListPreAuthKeysRequest, ListUsersRequest, Node,
    PreAuthKey, RegisterMethod, RegisterNodeRequest, RenameNodeRequest, RenameUserRequest,
    SetApprovedRoutesRequest, SetPolicyRequest, SetTagsRequest, User,
};
use crate::grpc::upstream::HeadscaleAdminService;

const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
struct GatewayState {
    service: HeadscaleAdminService,
    auth_service: HeadscaleAdminService,
}

/// Build a grpc-gateway-compatible router for implemented upstream RPCs.
///
/// The HTTP gateway is authenticated, matching headscale-go's
/// `apiRouter.Use(h.httpAuthenticationMiddleware)` in front of the
/// unauthenticated local gRPC socket.
pub fn router(service: HeadscaleAdminService) -> Router {
    let state = GatewayState {
        service: service.clone(),
        auth_service: service.require_api_key_auth(),
    };

    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/user", get(list_users).post(create_user))
        .route("/api/v1/user/:old_id/rename/:new_name", post(rename_user))
        .route("/api/v1/user/:id", delete(delete_user))
        .route(
            "/api/v1/preauthkey",
            get(list_preauth_keys)
                .post(create_preauth_key)
                .delete(delete_preauth_key),
        )
        .route("/api/v1/preauthkey/expire", post(expire_preauth_key))
        .route("/api/v1/apikey", get(list_api_keys).post(create_api_key))
        .route("/api/v1/apikey/expire", post(expire_api_key))
        .route("/api/v1/apikey/:prefix", delete(delete_api_key))
        .route("/api/v1/debug/node", post(debug_create_node))
        .route("/api/v1/node", get(list_nodes))
        .route("/api/v1/node/register", post(register_node))
        .route("/api/v1/node/backfillips", post(backfill_node_ips))
        .route("/api/v1/node/:node_id", get(get_node).delete(delete_node))
        .route("/api/v1/node/:node_id/tags", post(set_tags))
        .route(
            "/api/v1/node/:node_id/approve_routes",
            post(set_approved_routes),
        )
        .route("/api/v1/node/:node_id/expire", post(expire_node))
        .route("/api/v1/node/:node_id/rename/:new_name", post(rename_node))
        .route("/api/v1/policy", get(get_policy).put(set_policy))
        .route("/api/v1/policy/check", post(check_policy))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            http_authentication_middleware,
        ))
        .with_state(state)
}

async fn http_authentication_middleware(
    State(state): State<GatewayState>,
    request: Request,
    next: Next,
) -> Response {
    let metadata = authorization_metadata(request.headers());
    match state
        .auth_service
        .authorize_api_key_metadata(&metadata)
        .await
    {
        Ok(()) => next.run(request).await,
        Err(status) if status.code() == Code::Unauthenticated => plain_unauthorized_response(),
        Err(status) => status_response(&status),
    }
}

async fn health(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    match state
        .service
        .health(tonic_request(&headers, HealthRequest {}))
        .await
    {
        Ok(response) => json_ok(json!({
            "databaseConnectivity": response.into_inner().database_connectivity,
        })),
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct CreateUserBody {
    name: String,
    #[serde(rename = "displayName", alias = "display_name")]
    display_name: String,
    email: String,
    #[serde(rename = "pictureUrl", alias = "picture_url")]
    picture_url: String,
}

async fn create_user(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let body: CreateUserBody = match read_json(request).await {
        Ok(body) => body,
        Err(status) => return status_response(&status),
    };
    let request = tonic_request(
        &headers,
        CreateUserRequest {
            name: body.name,
            display_name: body.display_name,
            email: body.email,
            picture_url: body.picture_url,
        },
    );
    match state.service.create_user(request).await {
        Ok(response) => {
            let user = response.into_inner().user;
            json_ok(json!({ "user": optional_user_json(user.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ListUsersQuery {
    id: u64,
    name: String,
    email: String,
}

async fn list_users(
    State(state): State<GatewayState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: ListUsersQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    let request = tonic_request(
        &headers,
        ListUsersRequest {
            id: query.id,
            name: query.name,
            email: query.email,
        },
    );
    match state.service.list_users(request).await {
        Ok(response) => {
            let users = response
                .into_inner()
                .users
                .iter()
                .map(user_json)
                .collect::<Vec<_>>();
            json_ok(json!({ "users": users }))
        }
        Err(status) => status_response(&status),
    }
}

async fn rename_user(
    State(state): State<GatewayState>,
    Path((old_id, new_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let old_id = match parse_path_u64("old_id", &old_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    let request = tonic_request(&headers, RenameUserRequest { old_id, new_name });
    match state.service.rename_user(request).await {
        Ok(response) => {
            let user = response.into_inner().user;
            json_ok(json!({ "user": optional_user_json(user.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn delete_user(
    State(state): State<GatewayState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let id = match parse_path_u64("id", &id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    let request = tonic_request(&headers, DeleteUserRequest { id });
    match state.service.delete_user(request).await {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

async fn create_preauth_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let request = match create_preauth_request(&value) {
        Ok(body) => tonic_request(&headers, body),
        Err(status) => return status_response(&status),
    };
    match state.service.create_pre_auth_key(request).await {
        Ok(response) => {
            let pre_auth_key = response.into_inner().pre_auth_key;
            json_ok(json!({ "preAuthKey": optional_preauth_key_json(pre_auth_key.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn expire_preauth_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let id = match u64_field(&value, &["id"], "id") {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .expire_pre_auth_key(tonic_request(&headers, ExpirePreAuthKeyRequest { id }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct IdQuery {
    id: u64,
}

async fn delete_preauth_key(
    State(state): State<GatewayState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: IdQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .delete_pre_auth_key(tonic_request(
            &headers,
            DeletePreAuthKeyRequest { id: query.id },
        ))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

async fn list_preauth_keys(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    match state
        .service
        .list_pre_auth_keys(tonic_request(&headers, ListPreAuthKeysRequest {}))
        .await
    {
        Ok(response) => {
            let pre_auth_keys = response
                .into_inner()
                .pre_auth_keys
                .iter()
                .map(preauth_key_json)
                .collect::<Vec<_>>();
            json_ok(json!({ "preAuthKeys": pre_auth_keys }))
        }
        Err(status) => status_response(&status),
    }
}

async fn create_api_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let expiration = match timestamp_field(&value, &["expiration"], "expiration") {
        Ok(expiration) => expiration,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .create_api_key(tonic_request(&headers, CreateApiKeyRequest { expiration }))
        .await
    {
        Ok(response) => json_ok(json!({ "apiKey": response.into_inner().api_key })),
        Err(status) => status_response(&status),
    }
}

async fn expire_api_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let prefix = match string_field(&value, &["prefix"], "prefix") {
        Ok(prefix) => prefix,
        Err(status) => return status_response(&status),
    };
    let id = match u64_field(&value, &["id"], "id") {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .expire_api_key(tonic_request(&headers, ExpireApiKeyRequest { prefix, id }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

async fn list_api_keys(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    match state
        .service
        .list_api_keys(tonic_request(&headers, ListApiKeysRequest {}))
        .await
    {
        Ok(response) => {
            let api_keys = response
                .into_inner()
                .api_keys
                .iter()
                .map(api_key_json)
                .collect::<Vec<_>>();
            json_ok(json!({ "apiKeys": api_keys }))
        }
        Err(status) => status_response(&status),
    }
}

async fn delete_api_key(
    State(state): State<GatewayState>,
    Path(prefix): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: IdQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .delete_api_key(tonic_request(
            &headers,
            DeleteApiKeyRequest {
                prefix,
                id: query.id,
            },
        ))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

async fn debug_create_node(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let request = match debug_create_node_request(&value) {
        Ok(body) => tonic_request(&headers, body),
        Err(status) => return status_response(&status),
    };
    match state.service.debug_create_node(request).await {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RegisterNodeQuery {
    user: String,
    key: String,
}

async fn register_node(
    State(state): State<GatewayState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: RegisterNodeQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .register_node(tonic_request(
            &headers,
            RegisterNodeRequest {
                user: query.user,
                key: query.key,
            },
        ))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ListNodesQuery {
    user: String,
}

async fn list_nodes(
    State(state): State<GatewayState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: ListNodesQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .list_nodes(tonic_request(
            &headers,
            ListNodesRequest { user: query.user },
        ))
        .await
    {
        Ok(response) => {
            let nodes = response
                .into_inner()
                .nodes
                .iter()
                .map(node_json)
                .collect::<Vec<_>>();
            json_ok(json!({ "nodes": nodes }))
        }
        Err(status) => status_response(&status),
    }
}

async fn get_node(
    State(state): State<GatewayState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .get_node(tonic_request(&headers, GetNodeRequest { node_id }))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn set_tags(
    State(state): State<GatewayState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let tags = match string_array_field(&value, &["tags"], "tags") {
        Ok(tags) => tags,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .set_tags(tonic_request(&headers, SetTagsRequest { node_id, tags }))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn set_approved_routes(
    State(state): State<GatewayState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let routes = match string_array_field(&value, &["routes"], "routes") {
        Ok(routes) => routes,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .set_approved_routes(tonic_request(
            &headers,
            SetApprovedRoutesRequest { node_id, routes },
        ))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn delete_node(
    State(state): State<GatewayState>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .delete_node(tonic_request(&headers, DeleteNodeRequest { node_id }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

async fn expire_node(
    State(state): State<GatewayState>,
    Path(node_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    let expiry = match query_timestamp(raw_query.as_deref(), "expiry") {
        Ok(expiry) => expiry,
        Err(status) => return status_response(&status),
    };
    let disable_expiry =
        match query_bool(raw_query.as_deref(), "disableExpiry", &["disable_expiry"]) {
            Ok(disable_expiry) => disable_expiry,
            Err(status) => return status_response(&status),
        };
    match state
        .service
        .expire_node(tonic_request(
            &headers,
            ExpireNodeRequest {
                node_id,
                expiry,
                disable_expiry,
            },
        ))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

async fn rename_node(
    State(state): State<GatewayState>,
    Path((node_id, new_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let node_id = match parse_path_u64("node_id", &node_id) {
        Ok(id) => id,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .rename_node(tonic_request(
            &headers,
            RenameNodeRequest { node_id, new_name },
        ))
        .await
    {
        Ok(response) => {
            let node = response.into_inner().node;
            json_ok(json!({ "node": optional_node_json(node.as_ref()) }))
        }
        Err(status) => status_response(&status),
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BackfillNodeIpsQuery {
    confirmed: bool,
}

async fn backfill_node_ips(
    State(state): State<GatewayState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let query: BackfillNodeIpsQuery = match parse_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .backfill_node_i_ps(tonic_request(
            &headers,
            BackfillNodeIPsRequest {
                confirmed: query.confirmed,
            },
        ))
        .await
    {
        Ok(response) => json_ok(json!({ "changes": response.into_inner().changes })),
        Err(status) => status_response(&status),
    }
}

async fn get_policy(State(state): State<GatewayState>, headers: HeaderMap) -> Response {
    match state
        .service
        .get_policy(tonic_request(&headers, GetPolicyRequest {}))
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            json_ok(json!({
                "policy": response.policy,
                "updatedAt": timestamp_json(response.updated_at.as_ref()),
            }))
        }
        Err(status) => status_response(&status),
    }
}

async fn set_policy(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let policy = match string_field(&value, &["policy"], "policy") {
        Ok(policy) => policy,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .set_policy(tonic_request(&headers, SetPolicyRequest { policy }))
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            json_ok(json!({
                "policy": response.policy,
                "updatedAt": timestamp_json(response.updated_at.as_ref()),
            }))
        }
        Err(status) => status_response(&status),
    }
}

async fn check_policy(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(&status),
    };
    let policy = match string_field(&value, &["policy"], "policy") {
        Ok(policy) => policy,
        Err(status) => return status_response(&status),
    };
    match state
        .service
        .check_policy(tonic_request(&headers, CheckPolicyRequest { policy }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(&status),
    }
}

fn tonic_request<T>(headers: &HeaderMap, body: T) -> TonicRequest<T> {
    let mut request = TonicRequest::new(body);
    if let Some(value) = authorization_metadata(headers)
        .get("authorization")
        .cloned()
    {
        request.metadata_mut().insert("authorization", value);
    }
    request
}

fn authorization_metadata(headers: &HeaderMap) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    if let Some(value) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = value.to_str()
        && let Ok(value) = value.parse()
    {
        metadata.insert("authorization", value);
    }
    metadata
}

async fn read_json<T>(request: Request) -> Result<T, Status>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let body = to_bytes(request.into_body(), BODY_LIMIT)
        .await
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    if body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(&body).map_err(|e| Status::invalid_argument(e.to_string()))
}

async fn read_json_value(request: Request) -> Result<Value, Status> {
    let body = to_bytes(request.into_body(), BODY_LIMIT)
        .await
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    if body.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_slice(&body).map_err(|e| Status::invalid_argument(e.to_string()))
}

fn parse_query<T>(query: Option<&str>) -> Result<T, Status>
where
    T: for<'de> Deserialize<'de> + Default,
{
    match query {
        Some(query) if !query.is_empty() => {
            serde_urlencoded::from_str(query).map_err(|e| Status::invalid_argument(e.to_string()))
        }
        _ => Ok(T::default()),
    }
}

fn parse_path_u64(name: &str, value: &str) -> Result<u64, Status> {
    parse_go_uint64_base0(value).map_err(|e| {
        Status::invalid_argument(format!("type mismatch, parameter: {name}, error: {e}"))
    })
}

fn parse_go_uint64_base0(value: &str) -> Result<u64, String> {
    let (digits, radix, allow_prefix_underscore) = go_uint64_digits_and_radix(value)?;
    let digits = normalize_go_uint64_digits(value, digits, radix, allow_prefix_underscore)?;
    u64::from_str_radix(&digits, radix).map_err(|e| {
        let reason = match e.kind() {
            std::num::IntErrorKind::PosOverflow => "value out of range",
            _ => "invalid syntax",
        };
        go_parse_uint_error(value, reason)
    })
}

fn go_uint64_digits_and_radix(value: &str) -> Result<(&str, u32, bool), String> {
    if value.is_empty() || value.starts_with(['+', '-']) {
        return Err(go_parse_uint_error(value, "invalid syntax"));
    }
    if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return Ok((digits, 16, true));
    }
    if let Some(digits) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        return Ok((digits, 2, true));
    }
    if let Some(digits) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        return Ok((digits, 8, true));
    }
    if value.starts_with('0') && value.len() > 1 {
        return Ok((&value[1..], 8, true));
    }
    Ok((value, 10, false))
}

fn normalize_go_uint64_digits(
    original: &str,
    digits: &str,
    radix: u32,
    allow_prefix_underscore: bool,
) -> Result<String, String> {
    let mut normalized = String::with_capacity(digits.len());
    let mut previous_was_digit = false;
    let mut seen_digit = false;

    for (idx, ch) in digits.chars().enumerate() {
        if ch == '_' {
            if !(previous_was_digit || (idx == 0 && allow_prefix_underscore)) {
                return Err(go_parse_uint_error(original, "invalid syntax"));
            }
            previous_was_digit = false;
            continue;
        }

        let valid_digit = match radix {
            2 => matches!(ch, '0' | '1'),
            8 => matches!(ch, '0'..='7'),
            10 => ch.is_ascii_digit(),
            16 => ch.is_ascii_hexdigit(),
            _ => false,
        };
        if !valid_digit {
            return Err(go_parse_uint_error(original, "invalid syntax"));
        }
        normalized.push(ch);
        previous_was_digit = true;
        seen_digit = true;
    }

    if !seen_digit || !previous_was_digit {
        return Err(go_parse_uint_error(original, "invalid syntax"));
    }

    Ok(normalized)
}

fn go_parse_uint_error(value: &str, reason: &str) -> String {
    format!("strconv.ParseUint: parsing {value:?}: {reason}")
}

fn optional_user_json(user: Option<&User>) -> Value {
    user.map_or(Value::Null, user_json)
}

fn optional_preauth_key_json(preauth_key: Option<&PreAuthKey>) -> Value {
    preauth_key.map_or(Value::Null, preauth_key_json)
}

fn optional_node_json(node: Option<&Node>) -> Value {
    node.map_or(Value::Null, node_json)
}

fn user_json(user: &User) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), Value::String(user.id.to_string()));
    out.insert("name".into(), Value::String(user.name.clone()));
    out.insert("createdAt".into(), timestamp_json(user.created_at.as_ref()));
    out.insert(
        "displayName".into(),
        Value::String(user.display_name.clone()),
    );
    out.insert("email".into(), Value::String(user.email.clone()));
    out.insert("providerId".into(), Value::String(user.provider_id.clone()));
    out.insert("provider".into(), Value::String(user.provider.clone()));
    out.insert(
        "profilePicUrl".into(),
        Value::String(user.profile_pic_url.clone()),
    );
    Value::Object(out)
}

fn node_json(node: &Node) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), Value::String(node.id.to_string()));
    out.insert("machineKey".into(), Value::String(node.machine_key.clone()));
    out.insert("nodeKey".into(), Value::String(node.node_key.clone()));
    out.insert("discoKey".into(), Value::String(node.disco_key.clone()));
    out.insert(
        "ipAddresses".into(),
        Value::Array(
            node.ip_addresses
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert("name".into(), Value::String(node.name.clone()));
    out.insert("user".into(), optional_user_json(node.user.as_ref()));
    out.insert("lastSeen".into(), timestamp_json(node.last_seen.as_ref()));
    out.insert("expiry".into(), timestamp_json(node.expiry.as_ref()));
    out.insert(
        "preAuthKey".into(),
        optional_preauth_key_json(node.pre_auth_key.as_ref()),
    );
    out.insert("createdAt".into(), timestamp_json(node.created_at.as_ref()));
    out.insert(
        "registerMethod".into(),
        register_method_json(node.register_method),
    );
    out.insert("givenName".into(), Value::String(node.given_name.clone()));
    out.insert("online".into(), Value::Bool(node.online));
    out.insert(
        "approvedRoutes".into(),
        Value::Array(
            node.approved_routes
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert(
        "availableRoutes".into(),
        Value::Array(
            node.available_routes
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert(
        "subnetRoutes".into(),
        Value::Array(
            node.subnet_routes
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    out.insert(
        "tags".into(),
        Value::Array(node.tags.iter().cloned().map(Value::String).collect()),
    );
    Value::Object(out)
}

fn register_method_json(method: i32) -> Value {
    let method = RegisterMethod::try_from(method).unwrap_or(RegisterMethod::Unspecified);
    Value::String(method.as_str_name().to_string())
}

fn preauth_key_json(key: &PreAuthKey) -> Value {
    let mut out = Map::new();
    out.insert("user".into(), optional_user_json(key.user.as_ref()));
    out.insert("id".into(), Value::String(key.id.to_string()));
    out.insert("key".into(), Value::String(key.key.clone()));
    out.insert("reusable".into(), Value::Bool(key.reusable));
    out.insert("ephemeral".into(), Value::Bool(key.ephemeral));
    out.insert("used".into(), Value::Bool(key.used));
    out.insert("expiration".into(), timestamp_json(key.expiration.as_ref()));
    out.insert("createdAt".into(), timestamp_json(key.created_at.as_ref()));
    out.insert(
        "aclTags".into(),
        Value::Array(key.acl_tags.iter().cloned().map(Value::String).collect()),
    );
    Value::Object(out)
}

fn api_key_json(key: &ApiKey) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), Value::String(key.id.to_string()));
    out.insert("prefix".into(), Value::String(key.prefix.clone()));
    out.insert("expiration".into(), timestamp_json(key.expiration.as_ref()));
    out.insert("createdAt".into(), timestamp_json(key.created_at.as_ref()));
    out.insert("lastSeen".into(), timestamp_json(key.last_seen.as_ref()));
    Value::Object(out)
}

fn timestamp_json(ts: Option<&prost_types::Timestamp>) -> Value {
    let Some(ts) = ts else {
        return Value::Null;
    };
    match Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single() {
        Some(dt) => Value::String(dt.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        None => Value::Null,
    }
}

fn create_preauth_request(value: &Value) -> Result<CreatePreAuthKeyRequest, Status> {
    Ok(CreatePreAuthKeyRequest {
        user: u64_field(value, &["user"], "user")?,
        reusable: bool_field(value, &["reusable"], "reusable")?,
        ephemeral: bool_field(value, &["ephemeral"], "ephemeral")?,
        expiration: timestamp_field(value, &["expiration"], "expiration")?,
        acl_tags: string_array_field(value, &["aclTags", "acl_tags"], "aclTags")?,
    })
}

fn debug_create_node_request(value: &Value) -> Result<DebugCreateNodeRequest, Status> {
    Ok(DebugCreateNodeRequest {
        user: string_field(value, &["user"], "user")?,
        key: string_field(value, &["key"], "key")?,
        name: string_field(value, &["name"], "name")?,
        routes: string_array_field(value, &["routes"], "routes")?,
    })
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    let object = value.as_object()?;
    names.iter().find_map(|name| object.get(*name))
}

fn string_field(value: &Value, names: &[&str], display: &str) -> Result<String, Status> {
    match field(value, names) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Null) | None => Ok(String::new()),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid value for string field {display}"
        ))),
    }
}

fn bool_field(value: &Value, names: &[&str], display: &str) -> Result<bool, Status> {
    match field(value, names) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Null) | None => Ok(false),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid value for bool field {display}"
        ))),
    }
}

fn u64_field(value: &Value, names: &[&str], display: &str) -> Result<u64, Status> {
    match field(value, names) {
        Some(Value::String(s)) if !s.is_empty() => s.parse::<u64>().map_err(|e| {
            Status::invalid_argument(format!("type mismatch, parameter: {display}, error: {e}"))
        }),
        Some(Value::String(_) | Value::Null) | None => Ok(0),
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
            Status::invalid_argument(format!("invalid value for uint64 field {display}"))
        }),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid value for uint64 field {display}"
        ))),
    }
}

fn string_array_field(value: &Value, names: &[&str], display: &str) -> Result<Vec<String>, Status> {
    match field(value, names) {
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| match value {
                Value::String(s) => Ok(s.clone()),
                _ => Err(Status::invalid_argument(format!(
                    "invalid value for string array field {display}"
                ))),
            })
            .collect(),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid value for string array field {display}"
        ))),
    }
}

fn timestamp_field(
    value: &Value,
    names: &[&str],
    display: &str,
) -> Result<Option<prost_types::Timestamp>, Status> {
    match field(value, names) {
        Some(Value::String(s)) if !s.is_empty() => {
            let parsed = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| {
                Status::invalid_argument(format!("invalid timestamp field {display}: {e}"))
            })?;
            Ok(Some(prost_types::Timestamp {
                seconds: parsed.timestamp(),
                nanos: parsed.timestamp_subsec_nanos() as i32,
            }))
        }
        Some(Value::Object(object)) => {
            let seconds = object
                .get("seconds")
                .and_then(Value::as_i64)
                .ok_or_else(|| {
                    Status::invalid_argument(format!("invalid timestamp field {display}"))
                })?;
            let nanos = object.get("nanos").and_then(Value::as_i64).unwrap_or(0);
            if !(0..1_000_000_000).contains(&nanos) {
                return Err(Status::invalid_argument(format!(
                    "invalid timestamp field {display}"
                )));
            }
            Ok(Some(prost_types::Timestamp {
                seconds,
                nanos: nanos as i32,
            }))
        }
        Some(Value::String(_) | Value::Null) | None => Ok(None),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid timestamp field {display}"
        ))),
    }
}

fn query_timestamp(
    query: Option<&str>,
    name: &str,
) -> Result<Option<prost_types::Timestamp>, Status> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(None);
    };
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(query).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let mut direct = None;
    let mut seconds = None;
    let mut nanos = None;
    for (key, value) in pairs {
        if key == name {
            direct = Some(value);
        } else if key == format!("{name}.seconds") {
            seconds = Some(value);
        } else if key == format!("{name}.nanos") {
            nanos = Some(value);
        }
    }

    if let Some(value) = direct {
        if value.is_empty() {
            return Ok(None);
        }
        let parsed = chrono::DateTime::parse_from_rfc3339(&value).map_err(|e| {
            Status::invalid_argument(format!("invalid timestamp field {name}: {e}"))
        })?;
        return Ok(Some(prost_types::Timestamp {
            seconds: parsed.timestamp(),
            nanos: parsed.timestamp_subsec_nanos() as i32,
        }));
    }

    let Some(seconds) = seconds else {
        return Ok(None);
    };
    let seconds = seconds.parse::<i64>().map_err(|e| {
        Status::invalid_argument(format!(
            "type mismatch, parameter: {name}.seconds, error: {e}"
        ))
    })?;
    let nanos = match nanos {
        Some(nanos) if !nanos.is_empty() => nanos.parse::<i32>().map_err(|e| {
            Status::invalid_argument(format!(
                "type mismatch, parameter: {name}.nanos, error: {e}"
            ))
        })?,
        _ => 0,
    };
    if !(0..1_000_000_000).contains(&nanos) {
        return Err(Status::invalid_argument(format!(
            "invalid timestamp field {name}"
        )));
    }
    Ok(Some(prost_types::Timestamp { seconds, nanos }))
}

fn query_bool(query: Option<&str>, name: &str, aliases: &[&str]) -> Result<bool, Status> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(false);
    };
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(query).map_err(|e| Status::invalid_argument(e.to_string()))?;
    for (key, value) in pairs {
        if key == name || aliases.iter().any(|alias| key == *alias) {
            return value.parse::<bool>().map_err(|e| {
                Status::invalid_argument(format!("type mismatch, parameter: {key}, error: {e}"))
            });
        }
    }
    Ok(false)
}

fn json_ok(value: Value) -> Response {
    Json(value).into_response()
}

fn status_response(status: &Status) -> Response {
    if status.code() == Code::Unauthenticated {
        return plain_unauthorized_response();
    }

    let status_code = http_status_from_grpc(status.code());
    (
        status_code,
        Json(json!({
            "code": grpc_code_number(status.code()),
            "message": status.message(),
            "details": [],
        })),
    )
        .into_response()
}

fn plain_unauthorized_response() -> Response {
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

fn http_status_from_grpc(code: Code) -> StatusCode {
    match code {
        Code::Ok => StatusCode::OK,
        Code::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Code::Unknown | Code::Internal | Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        Code::InvalidArgument | Code::FailedPrecondition | Code::OutOfRange => {
            StatusCode::BAD_REQUEST
        }
        Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::AlreadyExists | Code::Aborted => StatusCode::CONFLICT,
        Code::PermissionDenied => StatusCode::FORBIDDEN,
        Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn grpc_code_number(code: Code) -> i32 {
    match code {
        Code::Ok => 0,
        Code::Cancelled => 1,
        Code::Unknown => 2,
        Code::InvalidArgument => 3,
        Code::DeadlineExceeded => 4,
        Code::NotFound => 5,
        Code::AlreadyExists => 6,
        Code::PermissionDenied => 7,
        Code::ResourceExhausted => 8,
        Code::FailedPrecondition => 9,
        Code::Aborted => 10,
        Code::OutOfRange => 11,
        Code::Unimplemented => 12,
        Code::Internal => 13,
        Code::Unavailable => 14,
        Code::DataLoss => 15,
        Code::Unauthenticated => 16,
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn parse_go_uint64_base0_matches_grpc_gateway_literals() {
        for (input, expected) in [
            ("0", 0),
            ("42", 42),
            ("1_000", 1000),
            ("0x2a", 42),
            ("0X2A", 42),
            ("0x_2a", 42),
            ("0b101010", 42),
            ("0B10_1010", 42),
            ("0o52", 42),
            ("052", 42),
            ("0_52", 42),
            ("18446744073709551615", u64::MAX),
        ] {
            assert_eq!(parse_go_uint64_base0(input), Ok(expected), "{input}");
        }
    }

    #[test]
    fn parse_go_uint64_base0_reports_go_style_errors() {
        for input in [
            "", "+1", "-1", "_1", "1_", "1__0", "0x", "0x_", "08", "１２",
        ] {
            let err = parse_go_uint64_base0(input).unwrap_err();
            assert_eq!(
                err,
                format!("strconv.ParseUint: parsing {input:?}: invalid syntax")
            );
        }

        assert_eq!(
            parse_go_uint64_base0("18446744073709551616").unwrap_err(),
            "strconv.ParseUint: parsing \"18446744073709551616\": value out of range"
        );
    }
}
