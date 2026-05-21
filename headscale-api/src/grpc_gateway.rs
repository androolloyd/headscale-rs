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
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tonic::{Code, Request as TonicRequest, Status};

use crate::generated::headscale_service_server::HeadscaleService;
use crate::generated::{
    ApiKey, CreateApiKeyRequest, CreatePreAuthKeyRequest, CreateUserRequest, DeleteApiKeyRequest,
    DeletePreAuthKeyRequest, DeleteUserRequest, ExpireApiKeyRequest, ExpirePreAuthKeyRequest,
    GetPolicyRequest, HealthRequest, ListApiKeysRequest, ListPreAuthKeysRequest, ListUsersRequest,
    PreAuthKey, RenameUserRequest, SetPolicyRequest, User,
};
use crate::grpc::upstream::HeadscaleAdminService;

const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
struct GatewayState {
    service: HeadscaleAdminService,
}

/// Build a grpc-gateway-compatible router for implemented upstream RPCs.
///
/// The HTTP gateway is authenticated, matching headscale-go's
/// `apiRouter.Use(h.httpAuthenticationMiddleware)` in front of the
/// unauthenticated local gRPC socket.
pub fn router(service: HeadscaleAdminService) -> Router {
    let state = GatewayState {
        service: service.require_api_key_auth(),
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
        .route("/api/v1/policy", get(get_policy).put(set_policy))
        .with_state(state)
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
        Err(status) => status_response(status),
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
        Err(status) => return status_response(status),
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
        Err(status) => status_response(status),
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
        Err(status) => return status_response(status),
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
        Err(status) => status_response(status),
    }
}

async fn rename_user(
    State(state): State<GatewayState>,
    Path((old_id, new_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let old_id = match parse_path_u64("old_id", &old_id) {
        Ok(id) => id,
        Err(status) => return status_response(status),
    };
    let request = tonic_request(&headers, RenameUserRequest { old_id, new_name });
    match state.service.rename_user(request).await {
        Ok(response) => {
            let user = response.into_inner().user;
            json_ok(json!({ "user": optional_user_json(user.as_ref()) }))
        }
        Err(status) => status_response(status),
    }
}

async fn delete_user(
    State(state): State<GatewayState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let id = match parse_path_u64("id", &id) {
        Ok(id) => id,
        Err(status) => return status_response(status),
    };
    let request = tonic_request(&headers, DeleteUserRequest { id });
    match state.service.delete_user(request).await {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(status),
    }
}

async fn create_preauth_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(status),
    };
    let request = match create_preauth_request(&value) {
        Ok(body) => tonic_request(&headers, body),
        Err(status) => return status_response(status),
    };
    match state.service.create_pre_auth_key(request).await {
        Ok(response) => {
            let pre_auth_key = response.into_inner().pre_auth_key;
            json_ok(json!({ "preAuthKey": optional_preauth_key_json(pre_auth_key.as_ref()) }))
        }
        Err(status) => status_response(status),
    }
}

async fn expire_preauth_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(status),
    };
    let id = match u64_field(&value, &["id"], "id") {
        Ok(id) => id,
        Err(status) => return status_response(status),
    };
    match state
        .service
        .expire_pre_auth_key(tonic_request(&headers, ExpirePreAuthKeyRequest { id }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(status),
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
        Err(status) => return status_response(status),
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
        Err(status) => status_response(status),
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
        Err(status) => status_response(status),
    }
}

async fn create_api_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(status),
    };
    let expiration = match timestamp_field(&value, &["expiration"], "expiration") {
        Ok(expiration) => expiration,
        Err(status) => return status_response(status),
    };
    match state
        .service
        .create_api_key(tonic_request(&headers, CreateApiKeyRequest { expiration }))
        .await
    {
        Ok(response) => json_ok(json!({ "apiKey": response.into_inner().api_key })),
        Err(status) => status_response(status),
    }
}

async fn expire_api_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(status),
    };
    let prefix = match string_field(&value, &["prefix"], "prefix") {
        Ok(prefix) => prefix,
        Err(status) => return status_response(status),
    };
    let id = match u64_field(&value, &["id"], "id") {
        Ok(id) => id,
        Err(status) => return status_response(status),
    };
    match state
        .service
        .expire_api_key(tonic_request(&headers, ExpireApiKeyRequest { prefix, id }))
        .await
    {
        Ok(_) => json_ok(json!({})),
        Err(status) => status_response(status),
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
        Err(status) => status_response(status),
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
        Err(status) => return status_response(status),
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
        Err(status) => status_response(status),
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
        Err(status) => status_response(status),
    }
}

async fn set_policy(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let value = match read_json_value(request).await {
        Ok(value) => value,
        Err(status) => return status_response(status),
    };
    let policy = match string_field(&value, &["policy"], "policy") {
        Ok(policy) => policy,
        Err(status) => return status_response(status),
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
        Err(status) => status_response(status),
    }
}

fn tonic_request<T>(headers: &HeaderMap, body: T) -> TonicRequest<T> {
    let mut request = TonicRequest::new(body);
    if let Some(value) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = value.to_str()
        && let Ok(value) = value.parse()
    {
        request.metadata_mut().insert("authorization", value);
    }
    request
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
    value.parse::<u64>().map_err(|e| {
        Status::invalid_argument(format!("type mismatch, parameter: {name}, error: {e}"))
    })
}

fn optional_user_json(user: Option<&User>) -> Value {
    user.map(user_json).unwrap_or(Value::Null)
}

fn optional_preauth_key_json(preauth_key: Option<&PreAuthKey>) -> Value {
    preauth_key.map(preauth_key_json).unwrap_or(Value::Null)
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
        Some(Value::String(_)) | Some(Value::Null) | None => Ok(0),
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
        Some(Value::String(_)) | Some(Value::Null) | None => Ok(None),
        Some(_) => Err(Status::invalid_argument(format!(
            "invalid timestamp field {display}"
        ))),
    }
}

fn json_ok(value: Value) -> Response {
    Json(value).into_response()
}

fn status_response(status: Status) -> Response {
    let status_code = http_status_from_grpc(status.code());
    let mut response = (
        status_code,
        Json(json!({
            "code": grpc_code_number(status.code()),
            "message": status.message(),
            "details": [],
        })),
    )
        .into_response();
    if status.code() == Code::Unauthenticated {
        if let Ok(value) = status.message().parse() {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

fn http_status_from_grpc(code: Code) -> StatusCode {
    match code {
        Code::Ok => StatusCode::OK,
        Code::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        Code::InvalidArgument => StatusCode::BAD_REQUEST,
        Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::AlreadyExists => StatusCode::CONFLICT,
        Code::PermissionDenied => StatusCode::FORBIDDEN,
        Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        Code::Aborted => StatusCode::CONFLICT,
        Code::OutOfRange => StatusCode::BAD_REQUEST,
        Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
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
