//! `headscale preauthkeys {create,list,expire}` over upstream-compatible
//! gRPC, with a legacy `/api/v1/preauthkeys` HTTP path kept for explicit
//! `--server` use.

use chrono::{DateTime, Utc};
use headscale_api::admin::{PreauthAdminKey, PreauthMintRequest};
use headscale_api::generated::{PreAuthKey as GrpcPreAuthKey, User as GrpcUser};
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::GrpcAdminClient;
use super::output::{OutputFormat, print_structured, print_table};

#[derive(Debug, Serialize)]
struct EmptyResponse {}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &AdminClient,
    user: &str,
    reusable: bool,
    ephemeral: bool,
    tags: Vec<String>,
    expires_in_secs: u64,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = PreauthMintRequest {
        user: user.to_string(),
        ttl_secs: expires_in_secs,
        reusable,
        ephemeral,
        tags,
    };
    let key: PreauthAdminKey = client.post_json("/preauthkeys", &body).await?;
    if fmt.is_structured() {
        print_structured(fmt, &key)?;
    } else {
        println!("{}", key.key);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_grpc(
    client: &mut GrpcAdminClient,
    user: u64,
    reusable: bool,
    ephemeral: bool,
    tags: Vec<String>,
    expires_in_secs: u64,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let key = PreauthOutput::from(
        client
            .create_pre_auth_key(
                user,
                reusable,
                ephemeral,
                expiration_unix(expires_in_secs),
                tags,
            )
            .await?,
    );
    if fmt.is_structured() {
        print_structured(fmt, &key)?;
    } else {
        println!("{}", key.key);
    }
    Ok(())
}

pub async fn list(
    client: &AdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut keys: Vec<PreauthAdminKey> = client.get_json("/preauthkeys").await?;
    if let Some(u) = user_filter {
        keys.retain(|k| k.user == u);
    }
    if fmt.is_structured() {
        print_structured(fmt, &keys)?;
    } else {
        render_keys(&keys);
    }
    Ok(())
}

pub async fn list_grpc(
    client: &mut GrpcAdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut keys: Vec<PreauthOutput> = client
        .list_pre_auth_keys()
        .await?
        .into_iter()
        .map(PreauthOutput::from)
        .collect();
    if let Some(u) = user_filter {
        keys.retain(|k| k.user.as_ref().is_some_and(|user| user.name == u));
    }
    if fmt.is_structured() {
        print_structured(fmt, &keys)?;
    } else {
        render_grpc_keys(&keys);
    }
    Ok(())
}

pub async fn expire(client: &AdminClient, prefix: &str) -> Result<(), AdminError> {
    let path = format!("/preauthkeys/{prefix}/expire");
    client.post_no_content(&path).await?;
    println!("Expired preauth key '{prefix}'");
    Ok(())
}

pub async fn expire_grpc(
    client: &mut GrpcAdminClient,
    id: Option<u64>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let id = id.unwrap_or_default();
    if id == 0 {
        return Err(AdminError::Usage(
            "missing --id parameter: missing parameters".into(),
        ));
    }
    client.expire_pre_auth_key(id).await?;
    print_result(fmt, "Key expired")
}

pub async fn delete_grpc(
    client: &mut GrpcAdminClient,
    id: Option<u64>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let id = id.unwrap_or_default();
    if id == 0 {
        return Err(AdminError::Usage(
            "missing --id parameter: missing parameters".into(),
        ));
    }
    client.delete_pre_auth_key(id).await?;
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

fn render_keys(keys: &[PreauthAdminKey]) {
    if keys.is_empty() {
        print_table(
            &[
                "ID",
                "Key/Prefix",
                "Reusable",
                "Ephemeral",
                "Used",
                "Expiration",
                "Created",
                "Owner",
            ],
            &[],
        );
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                k.id.to_string(),
                k.key.clone(),
                k.reusable.to_string(),
                k.ephemeral.to_string(),
                (k.redemptions > 0).to_string(),
                timestamp_display_u64(k.expires_at),
                timestamp_display_u64(k.created_at),
                owner_display(&k.user, &k.tags),
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "Key/Prefix",
            "Reusable",
            "Ephemeral",
            "Used",
            "Expiration",
            "Created",
            "Owner",
        ],
        &rows,
    );
}

fn render_grpc_keys(keys: &[PreauthOutput]) {
    if keys.is_empty() {
        print_table(
            &[
                "ID",
                "Key/Prefix",
                "Reusable",
                "Ephemeral",
                "Used",
                "Expiration",
                "Created",
                "Owner",
            ],
            &[],
        );
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                k.id.to_string(),
                k.key.clone(),
                k.reusable.to_string(),
                k.ephemeral.to_string(),
                k.used.to_string(),
                k.expires_at_display.clone(),
                k.created_at_display.clone(),
                owner_display(k.user.as_ref().map_or("", UserOutput::name), &k.acl_tags),
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "Key/Prefix",
            "Reusable",
            "Ephemeral",
            "Used",
            "Expiration",
            "Created",
            "Owner",
        ],
        &rows,
    );
}

fn expiration_unix(ttl_secs: u64) -> Option<i64> {
    if ttl_secs == 0 {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let expires_at = now.saturating_add(ttl_secs);
    i64::try_from(expires_at).ok()
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

fn timestamp_display_u64(ts: u64) -> String {
    if ts >= i64::MAX as u64 {
        return "-".into();
    }
    DateTime::<Utc>::from_timestamp(ts as i64, 0).map_or_else(
        || "-".into(),
        |time| time.format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

fn owner_display(user: &str, tags: &[String]) -> String {
    if !tags.is_empty() {
        tags.join("\n")
    } else if !user.is_empty() {
        user.to_string()
    } else {
        "-".into()
    }
}

/// Show the upstream display prefix for modern pre-auth keys.
#[cfg(test)]
fn short_prefix(key: &str) -> String {
    const TOKEN_PREFIX: &str = "hskey-auth-";
    const TOKEN_PREFIX_LEN: usize = 12;
    if let Some(rest) = key.strip_prefix(TOKEN_PREFIX)
        && rest.len() >= TOKEN_PREFIX_LEN
    {
        return format!("{TOKEN_PREFIX}{}-***", &rest[..TOKEN_PREFIX_LEN]);
    }
    key.to_string()
}

#[derive(Clone, Debug, Serialize)]
struct PreauthOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserOutput>,
    #[serde(skip_serializing_if = "is_zero_u64")]
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    key: String,
    #[serde(skip_serializing_if = "is_false")]
    reusable: bool,
    #[serde(skip_serializing_if = "is_false")]
    ephemeral: bool,
    #[serde(skip_serializing_if = "is_false")]
    used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    #[serde(rename = "acl_tags", skip_serializing_if = "Vec::is_empty")]
    acl_tags: Vec<String>,
    #[serde(skip)]
    expires_at_display: String,
    #[serde(skip)]
    created_at_display: String,
}

impl PreauthOutput {
    #[cfg(test)]
    fn matches_prefix(&self, prefix: &str) -> bool {
        self.key.starts_with(prefix) || short_prefix(&self.key) == prefix
    }
}

#[derive(Clone, Debug, Serialize)]
struct UserOutput {
    #[serde(skip_serializing_if = "is_zero_u64")]
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    email: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    provider_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_pic_url: String,
}

#[derive(Clone, Debug, Serialize)]
struct TimestampOutput {
    #[serde(skip_serializing_if = "is_zero_i64")]
    seconds: i64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    nanos: i32,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl UserOutput {
    fn name(&self) -> &str {
        &self.name
    }
}

impl From<GrpcUser> for UserOutput {
    fn from(user: GrpcUser) -> Self {
        Self {
            id: user.id,
            name: user.name,
            created_at: user.created_at.map(TimestampOutput::from),
            display_name: user.display_name,
            email: user.email,
            provider_id: user.provider_id,
            provider: user.provider,
            profile_pic_url: user.profile_pic_url,
        }
    }
}

impl From<prost_types::Timestamp> for TimestampOutput {
    fn from(ts: prost_types::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<GrpcPreAuthKey> for PreauthOutput {
    fn from(key: GrpcPreAuthKey) -> Self {
        let user = key.user.map(UserOutput::from);
        Self {
            user,
            id: key.id,
            key: key.key,
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            expires_at_display: timestamp_display_proto(key.expiration.as_ref()),
            expiration: key.expiration.map(TimestampOutput::from),
            created_at_display: timestamp_display_proto(key.created_at.as_ref()),
            created_at: key.created_at.map(TimestampOutput::from),
            acl_tags: key.acl_tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_prefix_truncates_long_keys() {
        let s = format!("hskey-auth-{}-{}", "a".repeat(12), "b".repeat(64));
        let out = short_prefix(&s);
        assert_eq!(out, "hskey-auth-aaaaaaaaaaaa-***");
    }

    #[test]
    fn short_prefix_passes_through_short_keys() {
        assert_eq!(short_prefix("short"), "short");
    }

    #[test]
    fn grpc_preauth_output_formats_and_matches_prefix() {
        let out = PreauthOutput::from(GrpcPreAuthKey {
            id: 42,
            key: "hskey-auth-abcdefghijkl-0123456789abcdef".to_string(),
            user: Some(headscale_api::generated::User {
                id: 7,
                name: "alice".into(),
                ..Default::default()
            }),
            reusable: true,
            ephemeral: false,
            used: false,
            expiration: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            created_at: None,
            acl_tags: vec!["tag:server".into()],
        });
        assert_eq!(out.id, 42);
        assert_eq!(out.user.as_ref().unwrap().name, "alice");
        assert_eq!(
            out.expiration.as_ref().map(|ts| ts.seconds),
            Some(1_704_067_200)
        );
        assert_eq!(out.acl_tags, vec!["tag:server"]);
        assert!(out.matches_prefix("hskey-auth-abcdefghijkl"));
        assert!(out.matches_prefix("hskey-auth-abcdefghijkl-***"));
        assert!(!out.matches_prefix("hskey-auth-deadbeef"));
    }
}
