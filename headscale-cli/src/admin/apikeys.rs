//! `headscale apikeys {create,list,expire,delete}` — wraps
//! `/api/v1/apikey`.

use std::time::{SystemTime, UNIX_EPOCH};

use headscale_api::admin::{ApiKeyAdminKey, ApiKeyCreated, ApiKeyMintRequest};
use serde::{Deserialize, Serialize};

use super::AdminError;
use super::client::AdminClient;
use super::duration::parse_duration_secs;
use super::output::{OutputFormat, print_json, print_table};

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
    let ttl_secs = parse_duration_secs(expiration).map_err(AdminError::Local)?;
    let ttl_secs = i64::try_from(ttl_secs)
        .map_err(|_| AdminError::Local(format!("duration '{expiration}' overflows i64")))?;
    let expires_at = now_unix()
        .checked_add(ttl_secs)
        .ok_or_else(|| AdminError::Local(format!("duration '{expiration}' overflows unix time")))?;
    let key: ApiKeyCreated = client
        .post_json(
            "/apikey",
            &ApiKeyMintRequest {
                expiration: Some(expires_at),
            },
        )
        .await?;
    match fmt {
        OutputFormat::Json => print_json(&key)?,
        OutputFormat::Table => {
            println!("{}", key.api_key);
        }
    }
    Ok(())
}

pub async fn list(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let response: ApiKeyListResponse = client.get_json("/apikey").await?;
    match fmt {
        OutputFormat::Json => print_json(&response.api_keys)?,
        OutputFormat::Table => render_keys(&response.api_keys),
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

fn identify(prefix: Option<&str>, id: Option<u64>) -> Result<ApiKeyIdentifyBody<'_>, AdminError> {
    match (prefix, id) {
        (None, None) => Err(AdminError::Local(
            "either --id or --prefix must be provided".into(),
        )),
        (Some(_), Some(_)) => Err(AdminError::Local(
            "only one of --id or --prefix can be provided".into(),
        )),
        (prefix, id) => Ok(ApiKeyIdentifyBody { prefix, id }),
    }
}

fn render_keys(keys: &[ApiKeyAdminKey]) {
    if keys.is_empty() {
        println!("No API keys.");
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                k.id.to_string(),
                k.prefix.clone(),
                format_optional_unix(k.expiration),
                k.created_at.to_string(),
            ]
        })
        .collect();
    print_table(&["ID", "PREFIX", "EXPIRATION", "CREATED_AT"], &rows);
}

fn format_optional_unix(v: Option<i64>) -> String {
    v.map_or_else(|| "-".into(), |ts| ts.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
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
}
