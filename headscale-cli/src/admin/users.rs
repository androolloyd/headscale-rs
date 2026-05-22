//! `headscale users {create,list,delete}` over upstream-compatible gRPC.
//!
//! Supplying `--server` keeps the legacy `/api/v1/users` transport available
//! for older admin HTTP deployments.

use headscale_api::admin::UserRecord;
use headscale_api::generated::User as GrpcUser;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::GrpcAdminClient;
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
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let user = grpc_user_to_record(client.create_user(name).await?);
    if fmt.is_structured() {
        print_structured(fmt, &user)?;
    } else {
        println!("Created user '{}'", user.name);
        render_users(&[user]);
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

pub async fn list_grpc(client: &mut GrpcAdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let users: Vec<UserRecord> = client
        .list_users(None)
        .await?
        .into_iter()
        .map(grpc_user_to_record)
        .collect();
    if fmt.is_structured() {
        print_structured(fmt, &users)?;
    } else {
        render_users(&users);
    }
    Ok(())
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

pub async fn delete_grpc(client: &mut GrpcAdminClient, name: &str) -> Result<(), AdminError> {
    let users = client.list_users(Some(name)).await?;
    let user = users
        .first()
        .ok_or_else(|| AdminError::NotFound(format!("user {name:?} not found")))?;
    client.delete_user_by_id(user.id).await?;
    println!("Deleted user '{name}'");
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

fn grpc_user_to_record(user: GrpcUser) -> UserRecord {
    let created_at = user
        .created_at
        .as_ref()
        .and_then(|ts| u64::try_from(ts.seconds).ok())
        .unwrap_or_default();
    UserRecord {
        id: user.id,
        name: user.name,
        created_at,
        last_activity: created_at,
        display_name: user.display_name,
        email: user.email,
        provider_id: user.provider_id,
        provider: user.provider,
        profile_pic_url: user.profile_pic_url,
    }
}
