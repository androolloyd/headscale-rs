// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause
// State.CreateUser/UpdateUser at headscale-go v0.29.5, with Gorm v1.31.1
// struct assignment rules. See UPSTREAM.md and retained upstream licenses.

//! State RPC writes differ from the legacy db.CreateUser/RenameUser helpers.
//! They do not validate a username or forbid renaming an OIDC user.

use chrono::{SecondsFormat, Utc};
#[cfg(feature = "postgres-sqlx")]
use sqlx::PgPool;
use sqlx::SqlitePool;

use super::{CreateParams, UserRow, UserWriteSnapshot};
use crate::{DbError, Result};

fn context(action: &str, error: impl Into<DbError>) -> DbError {
    DbError::General(format!(
        "{action} user: {}",
        error.into().headscale_go_message()
    ))
}

fn new_user(params: CreateParams) -> UserRow {
    let now = Utc::now();
    UserRow {
        id: 0,
        name: params.name,
        display_name: params.display_name,
        email: params.email,
        provider_identifier: params.provider_identifier,
        provider: params.provider,
        profile_pic_url: params.profile_pic_url,
        created_at: now.timestamp(),
        created_at_text: now.to_rfc3339_opts(SecondsFormat::Nanos, true),
        updated_at: now.timestamp(),
        deleted_at: None,
    }
}

/// Return the original create model. A trigger or a backend's timestamp
/// precision must not replace the accepted model with a post-save SQL read.
pub async fn create_for_state(pool: &SqlitePool, params: CreateParams) -> Result<UserRow> {
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|error| context("creating", error))?;
    let mut user = new_user(params);
    user.id = sqlx::query_scalar("INSERT INTO users (name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES (?,?,?,?,?,?,?,?,NULL) RETURNING id")
        .bind(&user.name).bind(&user.display_name).bind(&user.email)
        .bind(user.provider_identifier.as_deref()).bind(&user.provider).bind(&user.profile_pic_url)
        .bind(&user.created_at_text).bind(&user.created_at_text)
        .fetch_one(&mut *transaction).await.map_err(|error| context("creating", error))?;
    transaction
        .commit()
        .await
        .map_err(|error| context("creating", error))?;
    Ok(user)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_for_state(pool: &PgPool, params: CreateParams) -> Result<UserRow> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| context("creating", error))?;
    let mut user = new_user(params);
    let stored_clock = crate::preauth_keys::parse_database_timestamp(
        Some(user.created_at),
        Some(&user.created_at_text),
    )
    .expect("new model clock")
    .to_rfc3339_opts(SecondsFormat::Micros, true);
    user.id = sqlx::query_scalar("INSERT INTO users (name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES ($1,$2,$3,$4,$5,$6,$7::TIMESTAMPTZ,$7::TIMESTAMPTZ,NULL) RETURNING id")
        .bind(&user.name).bind(&user.display_name).bind(&user.email)
        .bind(user.provider_identifier.as_deref()).bind(&user.provider).bind(&user.profile_pic_url)
        .bind(stored_clock).fetch_one(&mut *transaction).await.map_err(|error| context("creating", error))?;
    transaction
        .commit()
        .await
        .map_err(|error| context("creating", error))?;
    Ok(user)
}

fn rename_fields(
    mut user: UserWriteSnapshot,
    name: &str,
    precision: SecondsFormat,
) -> Result<(UserRow, Vec<(&'static str, String)>)> {
    if user.row.id == 0 {
        // A zero Gorm primary key does not generate the implicit ID predicate;
        // the soft-delete scope alone cannot satisfy its update-WHERE guard.
        return Err(DbError::General(
            "updating user: WHERE conditions required".into(),
        ));
    }
    name.clone_into(&mut user.row.name);
    let mut fields = Vec::new();
    for (column, value) in [
        ("name", &user.row.name),
        ("display_name", &user.row.display_name),
        ("email", &user.row.email),
        ("provider", &user.row.provider),
        ("profile_pic_url", &user.row.profile_pic_url),
    ] {
        if !value.is_empty() {
            fields.push((column, value.clone()));
        }
    }
    if let Some(identifier) = &user.row.provider_identifier {
        // A valid sql.NullString containing "" is nonzero and is written.
        fields.push(("provider_identifier", identifier.clone()));
    }
    if !user.row.created_at_text.is_empty() {
        let created = crate::preauth_keys::parse_database_timestamp(
            Some(user.row.created_at),
            Some(&user.row.created_at_text),
        )
        .ok_or_else(|| DbError::General("invalid user creation time".into()))?;
        if created.timestamp() != -62_135_596_800 || created.timestamp_subsec_nanos() != 0 {
            fields.push(("created_at", created.to_rfc3339_opts(precision, true)));
        }
    }
    let now = Utc::now();
    user.row.updated_at = now.timestamp();
    fields.push(("updated_at", now.to_rfc3339_opts(precision, true)));
    Ok((user.row, fields))
}

pub async fn rename_for_state(pool: &SqlitePool, id: i64, name: &str) -> Result<UserRow> {
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let user = super::get_for_registration_on_connection(&mut transaction, id).await?;
    let (user, assignments) = rename_fields(user, name, SecondsFormat::Nanos)?;
    let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new("UPDATE users SET ");
    {
        let mut fields = query.separated(",");
        for (column, value) in assignments {
            fields
                .push(column)
                .push_unseparated("=")
                .push_bind_unseparated(value);
        }
    }
    query
        .push(" WHERE id=")
        .push_bind(id)
        .push(" AND deleted_at IS NULL");
    query
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(|error| context("updating", error))?;
    drop(query);
    transaction.commit().await?;
    // No affected-row rejection or post-save lookup. RPC RenameUser performs
    // its own by-name lookup after policy refresh and dispatch.
    Ok(user)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn rename_postgres_for_state(pool: &PgPool, id: i64, name: &str) -> Result<UserRow> {
    let mut transaction = pool.begin().await?;
    let user = super::get_postgres_for_registration_on_connection(&mut transaction, id).await?;
    let (user, assignments) = rename_fields(user, name, SecondsFormat::Micros)?;
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET ");
    {
        let mut fields = query.separated(",");
        for (column, value) in assignments {
            fields
                .push(column)
                .push_unseparated("=")
                .push_bind_unseparated(value);
            if matches!(column, "created_at" | "updated_at") {
                fields.push_unseparated("::TIMESTAMPTZ");
            }
        }
    }
    query
        .push(" WHERE id=")
        .push_bind(id)
        .push(" AND deleted_at IS NULL");
    query
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(|error| context("updating", error))?;
    drop(query);
    transaction.commit().await?;
    Ok(user)
}
