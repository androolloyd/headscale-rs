//! `headscale preauthkeys {create,list,expire}` over upstream-compatible
//! gRPC, with a legacy `/api/v1/preauthkeys` HTTP path kept for explicit
//! `--server` use.

use chrono::{DateTime, SecondsFormat, Utc};
use headscale_api::admin::{PreauthAdminKey, PreauthMintRequest};
use headscale_api::generated::PreAuthKey as GrpcPreAuthKey;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::{GrpcAdminClient, UserSelector};
use super::output::{OutputFormat, print_structured, print_table};

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
        // Mint flow is the one path that intentionally splashes
        // the full secret — the operator hands it to the device
        // and never sees it again.
        println!("Minted preauth key for user '{}':", key.user);
        println!("  {}", key.key);
        println!("  expires_at: {}", key.expires_at);
        println!("  reusable:   {}", key.reusable);
        println!("  ephemeral:  {}", key.ephemeral);
        if !key.tags.is_empty() {
            println!("  tags:       {}", key.tags.join(","));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_grpc(
    client: &mut GrpcAdminClient,
    user: &str,
    reusable: bool,
    ephemeral: bool,
    tags: Vec<String>,
    expires_in_secs: u64,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let user_id = resolve_user_id(client, user).await?;
    let key = PreauthOutput::from(
        client
            .create_pre_auth_key(
                user_id,
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
        println!("Minted preauth key for user '{}':", key.user);
        println!("  {}", key.key);
        println!("  expires_at: {}", key.expires_at_display);
        println!("  reusable:   {}", key.reusable);
        println!("  ephemeral:  {}", key.ephemeral);
        if !key.tags.is_empty() {
            println!("  tags:       {}", key.tags.join(","));
        }
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
        keys.retain(|k| k.user == u);
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

pub async fn expire_grpc(client: &mut GrpcAdminClient, prefix: &str) -> Result<(), AdminError> {
    let id = resolve_key_id(client, prefix).await?;
    client.expire_pre_auth_key(id).await?;
    println!("Expired preauth key '{prefix}'");
    Ok(())
}

pub async fn delete_grpc(
    client: &mut GrpcAdminClient,
    id: u64,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    if id == 0 {
        return Err(AdminError::Local("missing --id parameter".into()));
    }
    client.delete_pre_auth_key(id).await?;
    print_result(fmt, "Key deleted")
}

fn print_result(fmt: OutputFormat, message: &str) -> Result<(), AdminError> {
    #[derive(Serialize)]
    struct ResultOutput<'a> {
        #[serde(rename = "Result")]
        result: &'a str,
    }

    if fmt.is_structured() {
        print_structured(fmt, &ResultOutput { result: message })
    } else {
        println!("{message}");
        Ok(())
    }
}

async fn resolve_user_id(client: &mut GrpcAdminClient, user: &str) -> Result<u64, AdminError> {
    let users = client
        .list_users(UserSelector {
            id: None,
            name: Some(user),
            email: None,
        })
        .await?;
    match users.as_slice() {
        [user] => Ok(user.id),
        [] => Err(AdminError::NotFound(format!("user {user:?} not found"))),
        _ => Err(AdminError::Local(
            "multiple users match query, specify an ID".into(),
        )),
    }
}

async fn resolve_key_id(client: &mut GrpcAdminClient, prefix: &str) -> Result<u64, AdminError> {
    if prefix.len() < 4 {
        return Err(AdminError::Local(
            "prefix must be at least 4 chars".to_string(),
        ));
    }
    let matches: Vec<PreauthOutput> = client
        .list_pre_auth_keys()
        .await?
        .into_iter()
        .map(PreauthOutput::from)
        .filter(|key| key.matches_prefix(prefix))
        .collect();
    match matches.as_slice() {
        [key] => Ok(key.id),
        [] => Err(AdminError::NotFound(format!(
            "preauth key prefix {prefix:?} not found"
        ))),
        _ => Err(AdminError::Local(format!(
            "preauth key prefix {prefix:?} matched multiple keys"
        ))),
    }
}

fn render_keys(keys: &[PreauthAdminKey]) {
    if keys.is_empty() {
        println!("No preauth keys.");
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                short_prefix(&k.key),
                k.user.clone(),
                k.reusable.to_string(),
                k.ephemeral.to_string(),
                k.expires_at.to_string(),
                if k.tags.is_empty() {
                    "-".into()
                } else {
                    k.tags.join(",")
                },
            ]
        })
        .collect();
    print_table(
        &[
            "PREFIX",
            "USER",
            "REUSABLE",
            "EPHEMERAL",
            "EXPIRES_AT",
            "TAGS",
        ],
        &rows,
    );
}

fn render_grpc_keys(keys: &[PreauthOutput]) {
    if keys.is_empty() {
        println!("No preauth keys.");
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                short_prefix(&k.key),
                k.user.clone(),
                k.reusable.to_string(),
                k.ephemeral.to_string(),
                k.expires_at_display.clone(),
                if k.tags.is_empty() {
                    "-".into()
                } else {
                    k.tags.join(",")
                },
            ]
        })
        .collect();
    print_table(
        &[
            "PREFIX",
            "USER",
            "REUSABLE",
            "EPHEMERAL",
            "EXPIRES_AT",
            "TAGS",
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

fn timestamp_rfc3339(ts: Option<&prost_types::Timestamp>) -> Option<String> {
    let ts = ts?;
    let nanos = u32::try_from(ts.nanos).ok()?;
    DateTime::<Utc>::from_timestamp(ts.seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// Show the upstream display prefix for modern pre-auth keys.
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
    id: u64,
    key: String,
    user: String,
    reusable: bool,
    ephemeral: bool,
    used: bool,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip)]
    expires_at_display: String,
}

impl PreauthOutput {
    fn matches_prefix(&self, prefix: &str) -> bool {
        self.key.starts_with(prefix) || short_prefix(&self.key) == prefix
    }
}

impl From<GrpcPreAuthKey> for PreauthOutput {
    fn from(key: GrpcPreAuthKey) -> Self {
        let user = key.user.map_or_else(String::new, |user| user.name);
        let expires_at = timestamp_rfc3339(key.expiration.as_ref());
        Self {
            id: key.id,
            key: key.key,
            user,
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            tags: key.acl_tags,
            created_at: timestamp_rfc3339(key.created_at.as_ref()),
            expires_at_display: expires_at.clone().unwrap_or_else(|| "-".into()),
            expires_at,
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
        assert_eq!(out.user, "alice");
        assert_eq!(out.expires_at.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert!(out.matches_prefix("hskey-auth-abcdefghijkl"));
        assert!(out.matches_prefix("hskey-auth-abcdefghijkl-***"));
        assert!(!out.matches_prefix("hskey-auth-deadbeef"));
    }
}
