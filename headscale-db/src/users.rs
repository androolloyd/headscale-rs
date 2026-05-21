//! User persistence matching headscale-go v0.28.0.
//!
//! Upstream stores users in a `users` table with optional OIDC
//! provider identity fields and uniqueness rules around
//! `(name, provider_identifier)`. This module exposes that table with
//! Unix-second timestamps at the Rust boundary.

use crate::{DbError, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

const REGISTER_METHOD_OIDC: &str = "oidc";
const USER_COLUMNS: &str = r"
        id,
        COALESCE(name, '') AS name,
        COALESCE(display_name, '') AS display_name,
        COALESCE(email, '') AS email,
        provider_identifier,
        COALESCE(provider, '') AS provider,
        COALESCE(profile_pic_url, '') AS profile_pic_url,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
        CASE
            WHEN updated_at IS NULL THEN 0
            WHEN typeof(updated_at) = 'integer' THEN updated_at
            ELSE unixepoch(updated_at)
        END AS updated_at,
        CASE
            WHEN deleted_at IS NULL THEN NULL
            WHEN typeof(deleted_at) = 'integer' THEN deleted_at
            ELSE unixepoch(deleted_at)
        END AS deleted_at
";

fn user_select(suffix: &str) -> String {
    format!("SELECT {USER_COLUMNS} FROM users {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: Option<String>,
    pub provider: String,
    pub profile_pic_url: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

impl UserRow {
    pub fn username(&self) -> String {
        if !self.email.is_empty() {
            self.email.clone()
        } else if !self.name.is_empty() {
            self.name.clone()
        } else if let Some(id) = self
            .provider_identifier
            .as_ref()
            .filter(|id| !id.is_empty())
        {
            id.clone()
        } else {
            self.id.to_string()
        }
    }

    pub fn display(&self) -> String {
        if self.display_name.is_empty() {
            self.username()
        } else {
            self.display_name.clone()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateParams {
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: Option<String>,
    pub provider: String,
    pub profile_pic_url: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserError {
    #[error("user name invalid: {0}")]
    InvalidName(String),
    #[error("user already exists")]
    Exists,
    #[error("user not found")]
    NotFound,
    #[error("cannot edit OIDC user")]
    CannotChangeOidcUser,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn normalize_provider_identifier(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

pub fn validate_hostname(name: &str) -> std::result::Result<(), UserError> {
    if name.len() < 2 {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} is too short, must be at least 2 characters"
        )));
    }
    if name.len() > 63 {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} is too long, must not exceed 63 characters"
        )));
    }
    if name.to_lowercase() != name {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} must be lowercase (try {:?})",
            name.to_lowercase()
        )));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} cannot start or end with a hyphen"
        )));
    }
    if name.starts_with('.') || name.ends_with('.') {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} cannot start or end with a dot"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(UserError::InvalidName(format!(
            "hostname {name:?} contains invalid characters, only lowercase letters, numbers, hyphens and dots are allowed"
        )));
    }
    Ok(())
}

pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<UserRow> {
    validate_hostname(&params.name).map_err(|e| DbError::General(e.to_string()))?;
    let provider_identifier = normalize_provider_identifier(params.provider_identifier);
    let now = now_unix();
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO users
            (name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), NULL)
        RETURNING id
        ",
    )
    .bind(&params.name)
    .bind(&params.display_name)
    .bind(&params.email)
    .bind(&provider_identifier)
    .bind(&params.provider)
    .bind(&params.profile_pic_url)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(map_sqlx_err)?;
    get_by_id(pool, id).await
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<UserRow> {
    let query = user_select("WHERE id = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_name(pool: &SqlitePool, name: &str) -> Result<UserRow> {
    let query = user_select("WHERE name = ? AND deleted_at IS NULL ORDER BY id");
    let rows = sqlx::query_as::<_, UserRow>(&query)
        .bind(name)
        .fetch_all(pool)
        .await?;
    match rows.len() {
        0 => Err(DbError::NotFound(format!("user name={name}"))),
        1 => Ok(rows.into_iter().next().expect("len checked")),
        n => Err(DbError::General(format!(
            "expected exactly one user, found {n}"
        ))),
    }
}

pub async fn get_by_oidc_identifier(pool: &SqlitePool, id: &str) -> Result<UserRow> {
    let query = user_select("WHERE provider_identifier = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<UserRow>> {
    let query = user_select("WHERE deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, UserRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn rename(pool: &SqlitePool, id: i64, new_name: &str) -> Result<UserRow> {
    validate_hostname(new_name).map_err(|e| DbError::General(e.to_string()))?;
    let existing = get_by_id(pool, id).await?;
    if existing.provider == REGISTER_METHOD_OIDC {
        return Err(DbError::General(
            UserError::CannotChangeOidcUser.to_string(),
        ));
    }
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE users
        SET name = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(new_name)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("user id={id}")));
    }
    get_by_id(pool, id).await
}

pub async fn touch_by_name(pool: &SqlitePool, name: &str) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "
        UPDATE users
        SET updated_at = datetime(?, 'unixepoch')
        WHERE name = ? AND deleted_at IS NULL
        ",
    )
    .bind(now)
    .bind(name)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let affected = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("user id={id}")));
    }
    Ok(())
}

fn map_not_found(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound("user".into()),
        e => DbError::from(e),
    }
}

fn map_sqlx_err(e: sqlx::Error) -> DbError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DbError::General(UserError::Exists.to_string())
        }
        _ => DbError::from(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    fn alice() -> CreateParams {
        CreateParams {
            name: "alice".into(),
            display_name: "Alice Smith".into(),
            email: "alice@example.com".into(),
            provider_identifier: None,
            provider: "cli".into(),
            profile_pic_url: "https://example.com/alice.png".into(),
        }
    }

    #[tokio::test]
    async fn create_matches_headscale_go_row_shape() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        assert_eq!(user.id, 1);
        assert_eq!(user.name, "alice");
        assert_eq!(user.display_name, "Alice Smith");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.provider, "cli");
        assert_eq!(user.profile_pic_url, "https://example.com/alice.png");
        assert!(user.created_at > 0);
        assert_eq!(user.created_at, user.updated_at);

        let (name, created_at, updated_at, deleted_at): (String, i64, i64, Option<i64>) =
            sqlx::query_as(
                "
                SELECT name, unixepoch(created_at), unixepoch(updated_at), unixepoch(deleted_at)
                FROM users
                WHERE id = ?
                ",
            )
            .bind(user.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(name, "alice");
        assert_eq!(created_at, user.created_at);
        assert_eq!(updated_at, user.updated_at);
        assert_eq!(deleted_at, None);
    }

    #[tokio::test]
    async fn validates_hostnames_like_headscale_go() {
        assert!(validate_hostname("valid-hostname").is_ok());
        assert!(validate_hostname("valid.name").is_ok());
        assert!(validate_hostname("a").is_err());
        assert!(validate_hostname("Alice").is_err());
        assert!(validate_hostname("-alice").is_err());
        assert!(validate_hostname("alice-").is_err());
        assert!(validate_hostname(".alice").is_err());
        assert!(validate_hostname("alice.").is_err());
        assert!(validate_hostname("alice_smith").is_err());
        assert!(validate_hostname(&"a".repeat(64)).is_err());
    }

    #[tokio::test]
    async fn list_get_rename_destroy_round_trip() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        assert_eq!(get_by_id(db.pool(), user.id).await.unwrap().name, "alice");
        assert_eq!(get_by_name(db.pool(), "alice").await.unwrap().id, user.id);

        let renamed = rename(db.pool(), user.id, "bob").await.unwrap();
        assert_eq!(renamed.name, "bob");
        assert!(renamed.updated_at >= renamed.created_at);
        assert!(get_by_name(db.pool(), "alice").await.is_err());

        let users = list(db.pool()).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "bob");

        destroy(db.pool(), user.id).await.unwrap();
        assert!(list(db.pool()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn uniqueness_matches_headscale_go_indexes() {
        let db = fresh_db().await;
        create(db.pool(), alice()).await.unwrap();
        assert!(create(db.pool(), alice()).await.is_err());

        let oidc_a = CreateParams {
            name: "same".into(),
            provider_identifier: Some("issuer/a".into()),
            provider: REGISTER_METHOD_OIDC.into(),
            ..CreateParams::default()
        };
        let oidc_b = CreateParams {
            name: "same".into(),
            provider_identifier: Some("issuer/b".into()),
            provider: REGISTER_METHOD_OIDC.into(),
            ..CreateParams::default()
        };
        create(db.pool(), oidc_a.clone()).await.unwrap();
        create(db.pool(), oidc_b).await.unwrap();

        let duplicate_provider = CreateParams {
            name: "other".into(),
            ..oidc_a
        };
        assert!(create(db.pool(), duplicate_provider).await.is_err());
    }

    #[tokio::test]
    async fn get_by_name_reports_ambiguous_oidc_names_like_go() {
        let db = fresh_db().await;
        create(
            db.pool(),
            CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/a".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                ..CreateParams::default()
            },
        )
        .await
        .unwrap();
        create(
            db.pool(),
            CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/b".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                ..CreateParams::default()
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            get_by_name(db.pool(), "same").await.unwrap_err(),
            DbError::General(_)
        ));
    }

    #[tokio::test]
    async fn oidc_lookup_and_rename_rejection() {
        let db = fresh_db().await;
        let user = create(
            db.pool(),
            CreateParams {
                name: "oidc-user".into(),
                email: "oidc@example.com".into(),
                display_name: "OIDC User".into(),
                provider_identifier: Some("https://issuer/sub".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            get_by_oidc_identifier(db.pool(), "https://issuer/sub")
                .await
                .unwrap()
                .id,
            user.id
        );
        assert!(rename(db.pool(), user.id, "new-name").await.is_err());
    }

    #[tokio::test]
    async fn list_ignores_soft_deleted_go_rows() {
        let db = fresh_db().await;
        let now = now_unix();
        sqlx::query(
            "
            INSERT INTO users (name, created_at, updated_at, deleted_at)
            VALUES (?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
            ",
        )
        .bind("deleted")
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();
        assert!(list(db.pool()).await.unwrap().is_empty());
    }
}
