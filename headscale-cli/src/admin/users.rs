//! `headscale users {create,list,delete}` — wraps `/api/v1/users`.
//!
//! Response types are reused from `headscale_api::admin` so the wire
//! shape stays in lock-step with the server (#216 contract).

use headscale_api::admin::UserRecord;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
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

pub async fn list(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let users: Vec<UserRecord> = client.get_json("/users").await?;
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
