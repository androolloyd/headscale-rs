//! `headscale users` over upstream-compatible gRPC.
//!
//! Supplying `--server` keeps the legacy `/api/v1/users` transport available
//! for older admin HTTP deployments.

use std::collections::BTreeMap;
use std::io::{self, Write};

use chrono::{DateTime, Utc};
use headscale_api::admin::UserRecord;
use headscale_api::generated::User as GrpcUser;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::{GrpcAdminClient, UserSelector};
use super::output::{OutputFormat, print_structured, print_table};

/// `POST /api/v1/users` payload.
#[derive(Serialize)]
struct CreateUserBody<'a> {
    name: &'a str,
}

pub async fn create(client: &AdminClient, name: &str, fmt: OutputFormat) -> Result<(), AdminError> {
    let body = CreateUserBody { name };
    let user: UserRecord = client.post_json("/users", &body).await?;
    if fmt.is_structured() {
        print_structured(fmt, &user)?;
    } else {
        println!("Created user '{}'", user.name);
        render_users(&[user]);
    }
    Ok(())
}

pub async fn create_grpc(
    client: &mut GrpcAdminClient,
    name: &str,
    display_name: &str,
    email: &str,
    picture_url: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    validate_picture_url(picture_url)?;
    let user = UserOutput::from(
        client
            .create_user(name, display_name, email, picture_url)
            .await?,
    );
    if fmt.is_structured() {
        print_structured(fmt, &user)?;
    } else {
        println!("User created");
    }
    Ok(())
}

pub async fn list(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let users: Vec<UserRecord> = client.get_json("/users").await?;
    if fmt.is_structured() {
        print_structured(fmt, &users)?;
    } else {
        render_users(&users);
    }
    Ok(())
}

pub async fn list_grpc(
    client: &mut GrpcAdminClient,
    id: Option<i64>,
    name: Option<&str>,
    email: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let selector = list_selector(id, name, email);
    let users: Vec<UserOutput> = client
        .list_users(selector)
        .await?
        .into_iter()
        .map(UserOutput::from)
        .collect();
    if fmt.is_structured() {
        print_structured(fmt, &users)?;
    } else {
        render_grpc_users(&users);
    }
    Ok(())
}

pub(crate) fn parse_user_identifier(id: Option<&str>) -> Result<Option<i64>, AdminError> {
    id.map(|id| {
        id.parse::<i64>()
            .map_err(|_| AdminError::Usage(upstream_parse_int_error(id)))
    })
    .transpose()
}

fn upstream_parse_int_error(id: &str) -> String {
    let unsigned_digits = !id.is_empty() && id.chars().all(|c| c.is_ascii_digit());
    let signed_digits = id
        .strip_prefix('-')
        .or_else(|| id.strip_prefix('+'))
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
    let detail = if unsigned_digits || signed_digits {
        "value out of range"
    } else {
        "invalid syntax"
    };
    format!(
        "invalid argument \"{id}\" for \"-i, --identifier\" flag: strconv.ParseInt: parsing \"{id}\": {detail}"
    )
}

pub async fn delete(client: &AdminClient, name: &str) -> Result<(), AdminError> {
    // The admin router URL-routes on the raw name segment; `name` is
    // validated server-side, so we don't pre-encode here (the regex
    // accepted by the admin registry — `[a-z0-9_-]{1,32}` — is URL-safe).
    let path = format!("/users/{name}");
    client.delete_no_content(&path).await?;
    println!("Deleted user '{name}'");
    Ok(())
}

pub async fn destroy_grpc(
    client: &mut GrpcAdminClient,
    id: Option<i64>,
    name: Option<&str>,
    force: bool,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let user = resolve_single_user(client, id, name).await?;
    if !force
        && !confirm_action(&format!(
            "Do you want to remove the user {:?} ({}) and any associated preauthkeys?",
            user.name, user.id
        ))?
    {
        let message = "User not destroyed";
        if fmt.is_structured() {
            print_result(fmt, message)?;
        } else {
            println!("{message}");
        }
        return Ok(());
    }

    client.delete_user_by_id(user.id).await?;
    if fmt.is_structured() {
        print_structured(fmt, &BTreeMap::<String, String>::new())?;
    } else {
        println!("User destroyed");
    }
    Ok(())
}

pub async fn rename_grpc(
    client: &mut GrpcAdminClient,
    id: Option<i64>,
    name: Option<&str>,
    new_name: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let _user = resolve_single_user(client, id, name).await?;
    let renamed = UserOutput::from(
        client
            .rename_user_by_id(upstream_rename_request_id(id), new_name)
            .await?,
    );
    if fmt.is_structured() {
        print_structured(fmt, &renamed)?;
    } else {
        println!("User renamed");
    }
    Ok(())
}

/// Shared table renderer for the list-style outputs.
fn render_users(users: &[UserRecord]) {
    if users.is_empty() {
        println!("No users registered.");
        return;
    }
    let rows: Vec<Vec<String>> = users
        .iter()
        .map(|u| {
            vec![
                u.name.clone(),
                u.created_at.to_string(),
                u.last_activity.to_string(),
            ]
        })
        .collect();
    print_table(&["NAME", "CREATED", "LAST_ACTIVITY"], &rows);
}

fn render_grpc_users(users: &[UserOutput]) {
    let rows: Vec<Vec<String>> = users
        .iter()
        .map(|u| {
            vec![
                u.id.to_string(),
                u.display_name.clone(),
                u.name.clone(),
                u.email.clone(),
                u.created.clone(),
            ]
        })
        .collect();
    print_table(&["ID", "Name", "Username", "Email", "Created"], &rows);
}

async fn resolve_single_user(
    client: &mut GrpcAdminClient,
    id: Option<i64>,
    name: Option<&str>,
) -> Result<UserOutput, AdminError> {
    if !upstream_user_id_was_supplied(id) && name.unwrap_or_default().is_empty() {
        return Err(AdminError::Local(
            "--name or --identifier flag is required".into(),
        ));
    }
    let users = client
        .list_users(UserSelector {
            id: grpc_user_id_filter(id),
            name: name.filter(|value| !value.is_empty()),
            email: None,
        })
        .await?;
    if users.len() != 1 {
        return Err(AdminError::Local(
            "multiple users match query, specify an ID".into(),
        ));
    }
    users
        .into_iter()
        .next()
        .map(UserOutput::from)
        .ok_or_else(|| AdminError::Local("multiple users match query, specify an ID".into()))
}

fn list_selector<'a>(
    id: Option<i64>,
    name: Option<&'a str>,
    email: Option<&'a str>,
) -> UserSelector<'a> {
    if let Some(id) = grpc_user_id_filter(id) {
        UserSelector {
            id: Some(id),
            name: None,
            email: None,
        }
    } else if name.is_some_and(|value| !value.is_empty()) {
        UserSelector {
            id: None,
            name,
            email: None,
        }
    } else if email.is_some_and(|value| !value.is_empty()) {
        UserSelector {
            id: None,
            name: None,
            email,
        }
    } else {
        UserSelector::default()
    }
}

fn grpc_user_id_filter(id: Option<i64>) -> Option<u64> {
    id.filter(|id| *id > 0)
        .and_then(|id| u64::try_from(id).ok())
}

fn upstream_user_id_was_supplied(id: Option<i64>) -> bool {
    id.is_some_and(|id| id >= 0)
}

fn upstream_rename_request_id(id: Option<i64>) -> u64 {
    id.filter(|id| *id >= 0)
        .and_then(|id| u64::try_from(id).ok())
        .unwrap_or_default()
}

fn validate_picture_url(url: &str) -> Result<(), AdminError> {
    if url.bytes().any(|byte| byte.is_ascii_control()) || has_invalid_percent_escape(url) {
        return Err(AdminError::Local(format!("invalid picture URL: {url}")));
    }
    Ok(())
}

fn has_invalid_percent_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(hex) = bytes.get(index + 1..index + 3) else {
                return true;
            };
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn confirm_action(prompt: &str) -> Result<bool, AdminError> {
    eprint!("{prompt} [y/n] ");
    io::stderr()
        .flush()
        .map_err(|e| AdminError::Local(format!("write confirmation prompt: {e}")))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|e| AdminError::Local(format!("read confirmation response: {e}")))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "sure"
    ))
}

fn print_result(fmt: OutputFormat, message: &str) -> Result<(), AdminError> {
    #[derive(Serialize)]
    struct ResultOutput<'a> {
        #[serde(rename = "Result")]
        result: &'a str,
    }
    print_structured(fmt, &ResultOutput { result: message })
}

#[derive(Clone, Debug, Serialize)]
struct UserOutput {
    id: u64,
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
    #[serde(skip)]
    created: String,
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

impl From<GrpcUser> for UserOutput {
    fn from(user: GrpcUser) -> Self {
        let created_at = user.created_at;
        let created = created_at.as_ref().and_then(|ts| {
            let nanos = u32::try_from(ts.nanos).ok()?;
            DateTime::<Utc>::from_timestamp(ts.seconds, nanos)
        });
        Self {
            id: user.id,
            name: user.name,
            created_at: created_at.map(TimestampOutput::from),
            display_name: user.display_name,
            email: user.email,
            provider_id: user.provider_id,
            provider: user.provider,
            profile_pic_url: user.profile_pic_url,
            created: created
                .map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_list_selector_matches_upstream_filter_precedence() {
        assert_eq!(
            list_selector(Some(42), Some("alice"), Some("alice@example.com")).id,
            Some(42)
        );
        assert_eq!(list_selector(Some(0), None, None).id, None);
        assert_eq!(list_selector(Some(-1), None, None).id, None);
        let by_name = list_selector(None, Some("alice"), Some("alice@example.com"));
        assert_eq!(by_name.name, Some("alice"));
        assert_eq!(by_name.email, None);
        let by_email = list_selector(None, None, Some("alice@example.com"));
        assert_eq!(by_email.email, Some("alice@example.com"));
    }

    #[test]
    fn grpc_user_identifier_helpers_match_cobra_signed_flag_semantics() {
        assert!(!upstream_user_id_was_supplied(None));
        assert!(!upstream_user_id_was_supplied(Some(-1)));
        assert!(upstream_user_id_was_supplied(Some(0)));
        assert_eq!(parse_user_identifier(None).unwrap(), None);
        assert_eq!(parse_user_identifier(Some("42")).unwrap(), Some(42));
        assert_eq!(parse_user_identifier(Some("-1")).unwrap(), Some(-1));
        assert_eq!(
            parse_user_identifier(Some("abc")).unwrap_err().to_string(),
            "invalid argument \"abc\" for \"-i, --identifier\" flag: strconv.ParseInt: parsing \"abc\": invalid syntax"
        );
        assert_eq!(upstream_rename_request_id(None), 0);
        assert_eq!(upstream_rename_request_id(Some(-1)), 0);
        assert_eq!(upstream_rename_request_id(Some(42)), 42);
    }

    #[test]
    fn picture_url_validation_matches_upstream_permissive_parse() {
        assert!(validate_picture_url("").is_ok());
        assert!(validate_picture_url("https://example.com/alice.png").is_ok());
        assert!(validate_picture_url("avatar.png").is_ok());
        assert!(validate_picture_url("https://example.com/%zz").is_err());
        assert!(validate_picture_url("https://example.com/\n").is_err());
    }

    #[test]
    fn grpc_user_output_keeps_proto_timestamps_for_structured_output() {
        let out = UserOutput::from(GrpcUser {
            id: 7,
            name: "alice".into(),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            display_name: "Alice Example".into(),
            email: "alice@example.com".into(),
            provider_id: String::new(),
            provider: String::new(),
            profile_pic_url: "https://example.com/alice.png".into(),
        });
        assert_eq!(out.id, 7);
        assert_eq!(
            out.created_at.as_ref().map(|ts| ts.seconds),
            Some(1_704_067_200)
        );
        assert_eq!(out.created, "2024-01-01 00:00:00");
        assert_eq!(out.profile_pic_url, "https://example.com/alice.png");
    }
}
