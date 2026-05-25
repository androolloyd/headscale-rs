//! `headscale apikeys {create,list,expire,delete}` over upstream-compatible
//! gRPC, with a legacy `/api/v1/apikey` HTTP path kept for explicit
//! `--server` use.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use headscale_api::admin::{ApiKeyAdminKey, ApiKeyCreated, ApiKeyMintRequest};
use headscale_api::generated::ApiKey as GrpcApiKey;
use serde::{Deserialize, Serialize};

use super::AdminError;
use super::client::AdminClient;
use super::duration::parse_duration_secs;
use super::grpc_client::GrpcAdminClient;
use super::output::{OutputFormat, print_structured, print_table};

#[derive(Debug, Serialize)]
struct EmptyResponse {}

#[derive(Debug, Deserialize)]
struct ApiKeyListResponse {
    api_keys: Vec<ApiKeyAdminKey>,
}

#[derive(Debug, Serialize)]
struct ApiKeyIdentifyBody<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
}

pub async fn create(
    client: &AdminClient,
    expiration: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let expires_at = expiration_unix(expiration)?;
    let key: ApiKeyCreated = client
        .post_json(
            "/apikey",
            &ApiKeyMintRequest {
                expiration: Some(expires_at),
            },
        )
        .await?;
    if fmt.is_structured() {
        print_structured(fmt, &key.api_key)?;
    } else {
        println!("{}", key.api_key);
    }
    Ok(())
}

pub async fn create_grpc(
    client: &mut GrpcAdminClient,
    expiration: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let api_key = client
        .create_api_key(Some(expiration_unix(expiration)?))
        .await?;
    if fmt.is_structured() {
        print_structured(fmt, &api_key)?;
    } else {
        println!("{api_key}");
    }
    Ok(())
}

pub async fn list(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let response: ApiKeyListResponse = client.get_json("/apikey").await?;
    if fmt.is_structured() {
        print_structured(fmt, &response.api_keys)?;
    } else {
        render_keys(&response.api_keys);
    }
    Ok(())
}

pub async fn list_grpc(client: &mut GrpcAdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let keys: Vec<ApiKeyOutput> = client
        .list_api_keys()
        .await?
        .into_iter()
        .map(ApiKeyOutput::from)
        .collect();
    if fmt.is_structured() {
        print_structured(fmt, &keys)?;
    } else {
        render_grpc_keys(&keys);
    }
    Ok(())
}

pub async fn expire(
    client: &AdminClient,
    prefix: Option<&str>,
    id: Option<u64>,
) -> Result<(), AdminError> {
    let body = identify(prefix, id)?;
    client.post_json_no_content("/apikey/expire", &body).await?;
    println!("Key expired");
    Ok(())
}

pub async fn expire_grpc(
    client: &mut GrpcAdminClient,
    prefix: Option<&str>,
    id: Option<u64>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = identify(prefix, id)?;
    client.expire_api_key(body.prefix, body.id).await?;
    print_result(fmt, "Key expired")
}

pub async fn delete(
    client: &AdminClient,
    prefix: Option<&str>,
    id: Option<u64>,
) -> Result<(), AdminError> {
    let body = identify(prefix, id)?;
    client.delete_json_no_content("/apikey", &body).await?;
    println!("Key deleted");
    Ok(())
}

pub async fn delete_grpc(
    client: &mut GrpcAdminClient,
    prefix: Option<&str>,
    id: Option<u64>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = identify(prefix, id)?;
    client.delete_api_key(body.prefix, body.id).await?;
    print_result(fmt, "Key deleted")
}

fn print_result(fmt: OutputFormat, message: &str) -> Result<(), AdminError> {
    if fmt.is_structured() {
        print_structured(fmt, &EmptyResponse {})
    } else {
        println!("{message}");
        Ok(())
    }
}

fn identify(prefix: Option<&str>, id: Option<u64>) -> Result<ApiKeyIdentifyBody<'_>, AdminError> {
    match (prefix, id) {
        (None, None) => Err(AdminError::Usage(
            "either --id or --prefix must be provided: missing parameters".into(),
        )),
        (Some(_), Some(_)) => Err(AdminError::Usage(
            "only one of --id or --prefix can be provided: missing parameters".into(),
        )),
        (prefix, id) => Ok(ApiKeyIdentifyBody { prefix, id }),
    }
}

pub(super) fn validate_selector(prefix: Option<&str>, id: Option<u64>) -> Result<(), AdminError> {
    identify(prefix, id).map(|_| ())
}

fn expiration_unix(expiration: &str) -> Result<i64, AdminError> {
    let ttl_secs = parse_duration_secs(expiration).map_err(AdminError::Local)?;
    let ttl_secs = i64::try_from(ttl_secs)
        .map_err(|_| AdminError::Local(format!("duration '{expiration}' overflows i64")))?;
    now_unix()
        .checked_add(ttl_secs)
        .ok_or_else(|| AdminError::Local(format!("duration '{expiration}' overflows unix time")))
}

fn render_keys(keys: &[ApiKeyAdminKey]) {
    if keys.is_empty() {
        print_table(&["ID", "Prefix", "Expiration", "Created"], &[]);
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                k.id.to_string(),
                k.prefix.clone(),
                format_optional_unix(k.expiration),
                timestamp_display_i64(k.created_at),
            ]
        })
        .collect();
    print_table(&["ID", "Prefix", "Expiration", "Created"], &rows);
}

fn render_grpc_keys(keys: &[ApiKeyOutput]) {
    if keys.is_empty() {
        print_table(&["ID", "Prefix", "Expiration", "Created"], &[]);
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                k.id.to_string(),
                k.prefix.clone(),
                k.expiration_display.clone(),
                k.created_display.clone(),
            ]
        })
        .collect();
    print_table(&["ID", "Prefix", "Expiration", "Created"], &rows);
}

fn format_optional_unix(v: Option<i64>) -> String {
    v.map_or_else(|| "-".into(), timestamp_display_i64)
}

fn timestamp_display_i64(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0).map_or_else(
        || "-".into(),
        |time| time.format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

fn timestamp_display_proto(ts: Option<&prost_types::Timestamp>) -> String {
    ts.map_or_else(
        || "-".into(),
        |ts| {
            let nanos = u32::try_from(ts.nanos).ok();
            nanos
                .and_then(|nanos| DateTime::<Utc>::from_timestamp(ts.seconds, nanos))
                .map_or_else(
                    || "-".into(),
                    |time| time.format("%Y-%m-%d %H:%M:%S").to_string(),
                )
        },
    )
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[derive(Clone, Debug, Serialize)]
struct ApiKeyOutput {
    id: u64,
    prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<TimestampOutput>,
    #[serde(skip)]
    expiration_display: String,
    #[serde(skip)]
    created_display: String,
}

#[derive(Clone, Debug, Serialize)]
struct TimestampOutput {
    #[serde(skip_serializing_if = "is_zero_i64")]
    seconds: i64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    nanos: i32,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

impl From<prost_types::Timestamp> for TimestampOutput {
    fn from(ts: prost_types::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<GrpcApiKey> for ApiKeyOutput {
    fn from(key: GrpcApiKey) -> Self {
        let expiration_display = timestamp_display_proto(key.expiration.as_ref());
        let created_display = timestamp_display_proto(key.created_at.as_ref());
        Self {
            id: key.id,
            prefix: key.prefix,
            expiration: key.expiration.map(TimestampOutput::from),
            created_at: key.created_at.map(TimestampOutput::from),
            last_seen: key.last_seen.map(TimestampOutput::from),
            expiration_display,
            created_display,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_requires_exactly_one_selector() {
        assert!(identify(None, None).is_err());
        assert!(identify(Some("abc"), Some(1)).is_err());
        assert!(identify(Some("abc"), None).is_ok());
        assert!(identify(None, Some(1)).is_ok());
    }

    #[test]
    fn grpc_api_key_output_keeps_proto_timestamps_for_structured_output() {
        let out = ApiKeyOutput::from(GrpcApiKey {
            id: 7,
            prefix: "hskey-api-abcdefghijkl-***".into(),
            expiration: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_260,
                nanos: 0,
            }),
            last_seen: None,
        });
        assert_eq!(out.id, 7);
        assert_eq!(
            out.expiration.as_ref().map(|ts| ts.seconds),
            Some(1_704_067_200)
        );
        assert_eq!(
            out.created_at.as_ref().map(|ts| ts.seconds),
            Some(1_704_067_260)
        );
        assert!(out.last_seen.is_none());
    }

    #[test]
    fn grpc_api_key_output_serializes_proto_json_field_names() {
        let out = ApiKeyOutput::from(GrpcApiKey {
            id: 7,
            prefix: "hskey-api-abcdefghijkl-***".into(),
            expiration: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_260,
                nanos: 0,
            }),
            last_seen: Some(prost_types::Timestamp {
                seconds: 1_704_067_320,
                nanos: 0,
            }),
        });

        let value = serde_json::to_value(&out).unwrap();

        assert!(value.get("createdAt").is_none());
        assert!(value.get("lastSeen").is_none());
        assert_eq!(value["created_at"]["seconds"], 1_704_067_260);
        assert_eq!(value["last_seen"]["seconds"], 1_704_067_320);
    }
}
