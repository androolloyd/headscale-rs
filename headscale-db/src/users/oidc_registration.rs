// Copyright (c) 2020, Juan Font
// Copyright (c) 2013-present Jinzhu <wosmvp@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause AND MIT

//! OIDC returns the claim-mutated original user, while Updates saves a copy.
//! Empty string fields in that copy are omitted by Gorm's struct Updates.

use super::{OidcUserParams, REGISTER_METHOD_OIDC, UserRow, UserWriteSnapshot};
use crate::{DbError, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Connection, SqlitePool};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};

fn from_claim(
    user: Option<UserWriteSnapshot>,
    profile: OidcUserParams,
) -> Result<UserWriteSnapshot> {
    let identifier = super::normalize_oidc_provider_identifier(profile.provider_identifier)
        .map_err(|error| DbError::General(error.to_string()))?;
    let mut user = user.unwrap_or_else(|| UserWriteSnapshot {
        row: UserRow {
            id: 0,
            name: String::new(),
            display_name: String::new(),
            email: String::new(),
            provider_identifier: None,
            provider: String::new(),
            profile_pic_url: String::new(),
            created_at: 0,
            created_at_text: String::new(),
            updated_at: 0,
            deleted_at: None,
        },
        updated_at_text: String::new(),
        deleted_at_text: None,
    });
    // OidcUserProfile has already applied FromClaim's username/email checks.
    if !profile.name.is_empty() {
        user.row.name = profile.name;
    }
    if !profile.email.is_empty() {
        user.row.email = profile.email;
    }
    user.row.display_name = profile.display_name;
    user.row.provider_identifier = Some(identifier);
    user.row.provider = REGISTER_METHOD_OIDC.into();
    user.row.profile_pic_url = profile.profile_pic_url;
    Ok(user)
}

fn created_time(user: &UserWriteSnapshot) -> Result<Option<DateTime<Utc>>> {
    if user.row.created_at_text.is_empty() {
        return Ok(None);
    }
    let created = crate::preauth_keys::parse_database_timestamp(
        Some(user.row.created_at),
        Some(&user.row.created_at_text),
    )
    .ok_or_else(|| DbError::General("invalid OIDC user creation time".into()))?;
    Ok(
        (created.timestamp() != -62_135_596_800 || created.timestamp_subsec_nanos() != 0)
            .then_some(created),
    )
}

fn initialize_user_clock(user: &mut UserWriteSnapshot) {
    let now = Utc::now();
    user.row.created_at = now.timestamp();
    user.row.updated_at = now.timestamp();
    user.row.created_at_text = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    user.updated_at_text.clone_from(&user.row.created_at_text);
}

fn context(action: &str, error: impl Into<DbError>) -> DbError {
    DbError::General(format!(
        "{action} user: {}",
        error.into().headscale_go_message()
    ))
}

pub async fn create_or_update_oidc_user_for_registration(
    pool: &SqlitePool,
    profile: OidcUserParams,
) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    let query = format!(
        "SELECT {}, COALESCE(CAST(updated_at AS TEXT), '') AS updated_at_text, CAST(deleted_at AS TEXT) AS deleted_at_text FROM users WHERE provider_identifier = ? AND deleted_at IS NULL ORDER BY id LIMIT 1",
        super::USER_COLUMNS,
    );
    let original = sqlx::query_as::<_, UserWriteSnapshot>(&query)
        .bind(&profile.provider_identifier)
        .fetch_optional(&mut *connection)
        .await?;
    let new_user = original.is_none();
    let mut user = from_claim(original, profile)?;
    if new_user {
        initialize_user_clock(&mut user);
        let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
        user.row.id = sqlx::query_scalar("INSERT INTO users (name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,NULL) RETURNING id")
            .bind(&user.row.name)
            .bind(&user.row.display_name)
            .bind(&user.row.email)
            .bind(user.row.provider_identifier.as_deref())
            .bind(&user.row.provider)
            .bind(&user.row.profile_pic_url)
            .bind(&user.row.created_at_text)
            .bind(&user.updated_at_text)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| context("creating", error))?;
        transaction.commit().await?;
    } else {
        let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
        // UpdateUser first requires a still-visible current row, then replaces
        // its model with the original callback snapshot before struct Updates.
        super::get_for_registration_on_connection(&mut transaction, user.row.id).await?;
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new("UPDATE users SET ");
        {
            let mut fields = query.separated(",");
            for (column, value) in [
                ("name", &user.row.name),
                ("display_name", &user.row.display_name),
                ("email", &user.row.email),
                ("provider", &user.row.provider),
                ("profile_pic_url", &user.row.profile_pic_url),
            ] {
                if !value.is_empty() {
                    fields
                        .push(column)
                        .push_unseparated("=")
                        .push_bind_unseparated(value);
                }
            }
            fields
                .push("provider_identifier=")
                .push_bind_unseparated(user.row.provider_identifier.as_deref());
            if let Some(created) = created_time(&user)? {
                fields
                    .push("created_at=")
                    .push_bind_unseparated(created.to_rfc3339_opts(SecondsFormat::Nanos, true));
            }
            fields
                .push("updated_at=")
                .push_bind_unseparated(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true));
        }
        query
            .push(" WHERE id=")
            .push_bind(user.row.id)
            .push(" AND deleted_at IS NULL");
        query
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|error| context("updating", error))?;
        transaction.commit().await?;
    }
    Ok(user)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_or_update_oidc_user_postgres_for_registration(
    pool: &PgPool,
    profile: OidcUserParams,
) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    create_or_update_oidc_user_postgres_for_registration_on_connection(&mut connection, profile)
        .await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_or_update_oidc_user_postgres_for_registration_on_connection(
    connection: &mut PgConnection,
    profile: OidcUserParams,
) -> Result<UserWriteSnapshot> {
    let query = format!(
        r#"SELECT {}, COALESCE(to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS updated_at_text, to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS deleted_at_text FROM users WHERE provider_identifier = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1"#,
        super::POSTGRES_USER_COLUMNS,
    );
    let original = sqlx::query_as::<_, UserWriteSnapshot>(&query)
        .bind(&profile.provider_identifier)
        .fetch_optional(&mut *connection)
        .await?;
    let new_user = original.is_none();
    let mut user = from_claim(original, profile)?;
    if new_user {
        initialize_user_clock(&mut user);
        let mut transaction = connection.begin().await?;
        let created = crate::preauth_keys::parse_database_timestamp(
            Some(user.row.created_at),
            Some(&user.row.created_at_text),
        )
        .expect("initialized clock")
        .to_rfc3339_opts(SecondsFormat::Micros, true);
        user.row.id = sqlx::query_scalar("INSERT INTO users (name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES ($1,$2,$3,$4,$5,$6,$7::TIMESTAMPTZ,$7::TIMESTAMPTZ,NULL) RETURNING id")
            .bind(&user.row.name)
            .bind(&user.row.display_name)
            .bind(&user.row.email)
            .bind(user.row.provider_identifier.as_deref())
            .bind(&user.row.provider)
            .bind(&user.row.profile_pic_url)
            .bind(created)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| context("creating", error))?;
        transaction.commit().await?;
    } else {
        let mut transaction = connection.begin().await?;
        super::get_postgres_for_registration_on_connection(&mut transaction, user.row.id).await?;
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET ");
        {
            let mut fields = query.separated(",");
            for (column, value) in [
                ("name", &user.row.name),
                ("display_name", &user.row.display_name),
                ("email", &user.row.email),
                ("provider", &user.row.provider),
                ("profile_pic_url", &user.row.profile_pic_url),
            ] {
                if !value.is_empty() {
                    fields
                        .push(column)
                        .push_unseparated("=")
                        .push_bind_unseparated(value);
                }
            }
            fields
                .push("provider_identifier=")
                .push_bind_unseparated(user.row.provider_identifier.as_deref());
            if let Some(created) = created_time(&user)? {
                fields
                    .push("created_at=")
                    .push_bind_unseparated(created.to_rfc3339_opts(SecondsFormat::Micros, true))
                    .push_unseparated("::TIMESTAMPTZ");
            }
            fields
                .push("updated_at=")
                .push_bind_unseparated(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true))
                .push_unseparated("::TIMESTAMPTZ");
        }
        query
            .push(" WHERE id=")
            .push_bind(user.row.id)
            .push(" AND deleted_at IS NULL");
        query
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(|error| context("updating", error))?;
        transaction.commit().await?;
    }
    Ok(user)
}
