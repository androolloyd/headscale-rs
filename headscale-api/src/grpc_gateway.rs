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
    CreateUserRequest, DeleteUserRequest, HealthRequest, ListUsersRequest, RenameUserRequest, User,
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

fn timestamp_json(ts: Option<&prost_types::Timestamp>) -> Value {
    let Some(ts) = ts else {
        return Value::Null;
    };
    match Utc.timestamp_opt(ts.seconds, ts.nanos as u32).single() {
        Some(dt) => Value::String(dt.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        None => Value::Null,
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
