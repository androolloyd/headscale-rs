// Copyright (c) 2020, Juan Font
// Copyright (c) 2013-present Jinzhu <wosmvp@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause AND MIT

//! Fresh Gorm Save writes captured belongs-to associations before the node.
//! Sensitive key material is transient and never becomes a node-cache value.

use super::{HeadscaleNodeRow, NewNodeRegistration};
use crate::{DbError, Result, preauth_keys::RegistrationKey, users::UserWriteSnapshot};
use chrono::{DateTime, SecondsFormat, Utc};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};

#[derive(Clone, Default)]
pub enum NewNodeAssociations {
    #[default]
    None,
    User(Box<UserWriteSnapshot>),
    AuthKey(Box<RegistrationKey>),
}

pub struct NewNodeSave {
    pub node: HeadscaleNodeRow,
    pub associations: NewNodeAssociations,
}

/// Compatibility-shaped node insertion still runs the same captured
/// belongs-to callback before its existing name selection and row insert.
pub async fn create_with_associations(
    pool: &SqlitePool,
    params: super::CreateParams,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    let saved = create_with_associations_on_connection(&mut transaction, params, associations)
        .await
        .map_err(saving_node)?;
    transaction.commit().await?;
    Ok(saved)
}

pub async fn create_with_associations_on_connection(
    connection: &mut SqliteConnection,
    mut params: super::CreateParams,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let associations = save_sqlite_associations(
        connection,
        &mut params.user_id,
        &mut params.auth_key_id,
        associations,
    )
    .await?;
    let node = super::create_on_connection(connection, params).await?;
    Ok(NewNodeSave { node, associations })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_associations(
    pool: &PgPool,
    params: super::CreateParams,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let mut transaction = pool.begin().await.map_err(saving_node)?;
    let saved =
        create_postgres_with_associations_on_connection(&mut transaction, params, associations)
            .await
            .map_err(saving_node)?;
    transaction.commit().await?;
    Ok(saved)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_associations_on_connection(
    connection: &mut PgConnection,
    mut params: super::CreateParams,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let associations = save_postgres_associations(
        connection,
        &mut params.user_id,
        &mut params.auth_key_id,
        associations,
    )
    .await?;
    let node = super::create_postgres_on_connection(connection, params).await?;
    Ok(NewNodeSave { node, associations })
}

impl NewNodeSave {
    pub(crate) fn note_key_used(&mut self) {
        if let NewNodeAssociations::AuthKey(key) = &mut self.associations {
            key.key.used_at = Some(key.key.expiration.unwrap_or(key.key.created_at));
        }
    }
}

fn model_time(raw: &str, seconds: i64) -> Result<DateTime<Utc>> {
    if raw.is_empty() {
        return DateTime::from_timestamp(-62_135_596_800, 0)
            .ok_or_else(|| DbError::General("invalid Go zero time".into()));
    }
    crate::preauth_keys::parse_database_timestamp(Some(seconds), Some(raw))
        .ok_or_else(|| DbError::General("invalid captured user timestamp".into()))
}

fn prepare_user(mut user: UserWriteSnapshot) -> Result<UserWriteSnapshot> {
    if user.row.id < 0 {
        return Err(DbError::General("invalid captured user identity".into()));
    }
    let now = Utc::now();
    let created = model_time(&user.row.created_at_text, user.row.created_at)?;
    let updated = model_time(&user.updated_at_text, user.row.updated_at)?;
    let is_zero = |time: DateTime<Utc>| {
        time.timestamp() == -62_135_596_800 && time.timestamp_subsec_nanos() == 0
    };
    let created = if is_zero(created) { now } else { created };
    let updated = if is_zero(updated) { now } else { updated };
    user.row.created_at = created.timestamp();
    user.row.created_at_text = created.to_rfc3339_opts(SecondsFormat::Nanos, true);
    user.row.updated_at = updated.timestamp();
    user.updated_at_text = updated.to_rfc3339_opts(SecondsFormat::Nanos, true);
    Ok(user)
}

fn user_times(
    user: &UserWriteSnapshot,
    precision: SecondsFormat,
) -> Result<(String, String, Option<String>)> {
    let created = model_time(&user.row.created_at_text, user.row.created_at)?
        .to_rfc3339_opts(precision, true);
    let updated =
        model_time(&user.updated_at_text, user.row.updated_at)?.to_rfc3339_opts(precision, true);
    let deleted = user
        .deleted_at_text
        .as_deref()
        .map(|raw| {
            model_time(raw, user.row.deleted_at.unwrap_or(0))
                .map(|time| time.to_rfc3339_opts(precision, true))
        })
        .transpose()?;
    Ok((created, updated, deleted))
}

fn prepare_key(mut key: RegistrationKey) -> Result<RegistrationKey> {
    if key.key.id < 0 {
        return Err(DbError::General(
            "invalid captured preauth key identity".into(),
        ));
    }
    if key.key.created_at_text.is_empty() {
        let now = Utc::now();
        key.key.created_at = now.timestamp();
        key.key.created_at_text = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    }
    // Go's nullable SQL strings scan into ordinary string fields.
    key.key.key = Some(key.key.key.unwrap_or_default());
    key.key.prefix = Some(key.key.prefix.unwrap_or_default());
    Ok(key)
}

/// `(user_id, tags_json, created_at, expiration)` as bound for the INSERT.
type KeyValues = (Option<i64>, Option<String>, String, Option<String>);

fn key_values(key: &RegistrationKey, precision: SecondsFormat) -> Result<KeyValues> {
    let user_id =
        if key.key.user_id.is_empty() {
            None
        } else {
            Some(key.key.user_id.parse::<i64>().map_err(|_| {
                DbError::General("invalid captured preauth key user identity".into())
            })?)
        };
    let tags = if key.tags_nil {
        None
    } else {
        Some(super::json_array(&key.key.try_tag_list()?)?)
    };
    let created =
        model_time(&key.key.created_at_text, key.key.created_at)?.to_rfc3339_opts(precision, true);
    let expiry = key
        .key
        .expiration_text
        .as_deref()
        .map(|raw| {
            crate::preauth_keys::parse_database_timestamp(key.key.expiration, Some(raw))
                .map(|time| time.to_rfc3339_opts(precision, true))
                .ok_or_else(|| DbError::General("invalid captured preauth key expiry".into()))
        })
        .transpose()?;
    Ok((user_id, tags, created, expiry))
}

fn saving_node(error: impl Into<DbError>) -> DbError {
    let error = error.into();
    DbError::General(format!("saving node: {}", error.headscale_go_message()))
}

pub(crate) async fn save_sqlite_user(
    connection: &mut SqliteConnection,
    user: UserWriteSnapshot,
) -> Result<UserWriteSnapshot> {
    let mut user = prepare_user(user)?;
    let (created, updated, deleted) = user_times(&user, SecondsFormat::Nanos)?;
    let id = {
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new("INSERT INTO users (");
        if user.row.id != 0 {
            query.push("id,");
        }
        query.push("name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES (");
        if user.row.id != 0 {
            query.push_bind(user.row.id).push(",");
        }
        query
            .push_bind(&user.row.name)
            .push(",")
            .push_bind(&user.row.display_name)
            .push(",")
            .push_bind(&user.row.email)
            .push(",")
            .push_bind(user.row.provider_identifier.as_deref())
            .push(",")
            .push_bind(&user.row.provider)
            .push(",")
            .push_bind(&user.row.profile_pic_url)
            .push(",")
            .push_bind(&created)
            .push(",")
            .push_bind(&updated)
            .push(",")
            .push_bind(deleted.as_deref())
            .push(") ON CONFLICT DO NOTHING RETURNING id");
        query
            .build_query_scalar::<i64>()
            .fetch_optional(&mut *connection)
            .await?
    };
    if let Some(id) = id {
        user.row.id = id;
    }
    Ok(user)
}

async fn save_sqlite_key(
    connection: &mut SqliteConnection,
    mut key: RegistrationKey,
) -> Result<RegistrationKey> {
    if let Some(user) = key.user.take() {
        let user = save_sqlite_user(connection, user).await?;
        key.key.user_id = user.row.id.to_string();
        key.user = Some(user);
    }
    let mut key = prepare_key(key)?;
    let (user_id, tags, created, expiry) = key_values(&key, SecondsFormat::Nanos)?;
    let id = {
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new("INSERT INTO pre_auth_keys (");
        if key.key.id != 0 {
            query.push("id,");
        }
        query.push(
            "key,prefix,hash,user_id,reusable,ephemeral,used,tags,created_at,expiration) VALUES (",
        );
        if key.key.id != 0 {
            query.push_bind(key.key.id).push(",");
        }
        query
            .push_bind(key.key.key.as_deref())
            .push(",")
            .push_bind(key.key.prefix.as_deref())
            .push(",")
            .push_bind(key.hash.as_deref())
            .push(",")
            .push_bind(user_id)
            .push(",")
            .push_bind(key.key.reusable)
            .push(",")
            .push_bind(key.key.ephemeral)
            .push(",")
            .push_bind(key.key.used_at.is_some())
            .push(",")
            .push_bind(tags.as_deref())
            .push(",")
            .push_bind(&created)
            .push(",")
            .push_bind(expiry.as_deref())
            .push(") ON CONFLICT DO NOTHING RETURNING id");
        query
            .build_query_scalar::<i64>()
            .fetch_optional(&mut *connection)
            .await?
    };
    if let Some(id) = id {
        key.key.id = id;
    }
    key.key.tags = tags.unwrap_or_else(|| "null".into());
    Ok(key)
}

pub async fn create_new_registration_with_associations(
    pool: &SqlitePool,
    node: NewNodeRegistration,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_node)?;
    let saved = create_new_registration_with_associations_on_connection(
        &mut transaction,
        node,
        associations,
    )
    .await
    .map_err(saving_node)?;
    transaction.commit().await?;
    Ok(saved)
}

pub async fn create_new_registration_with_associations_on_connection(
    connection: &mut SqliteConnection,
    mut node: NewNodeRegistration,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let associations = save_sqlite_associations(
        connection,
        &mut node.user_id,
        &mut node.auth_key_id,
        associations,
    )
    .await?;
    let node = super::create_new_registration_on_connection(connection, node).await?;
    Ok(NewNodeSave { node, associations })
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) async fn save_postgres_user(
    connection: &mut PgConnection,
    user: UserWriteSnapshot,
) -> Result<UserWriteSnapshot> {
    let mut user = prepare_user(user)?;
    let (created, updated, deleted) = user_times(&user, SecondsFormat::Micros)?;
    let id = {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("INSERT INTO users (");
        if user.row.id != 0 {
            query.push("id,");
        }
        query.push("name,display_name,email,provider_identifier,provider,profile_pic_url,created_at,updated_at,deleted_at) VALUES (");
        if user.row.id != 0 {
            query.push_bind(user.row.id).push(",");
        }
        query
            .push_bind(&user.row.name)
            .push(",")
            .push_bind(&user.row.display_name)
            .push(",")
            .push_bind(&user.row.email)
            .push(",")
            .push_bind(user.row.provider_identifier.as_deref())
            .push(",")
            .push_bind(&user.row.provider)
            .push(",")
            .push_bind(&user.row.profile_pic_url)
            .push(",")
            .push_bind(&created)
            .push("::TIMESTAMPTZ")
            .push(",")
            .push_bind(&updated)
            .push("::TIMESTAMPTZ")
            .push(",")
            .push_bind(deleted.as_deref())
            .push("::TIMESTAMPTZ")
            .push(") ON CONFLICT DO NOTHING RETURNING id");
        query
            .build_query_scalar::<i64>()
            .fetch_optional(&mut *connection)
            .await?
    };
    if let Some(id) = id {
        user.row.id = id;
    }
    Ok(user)
}

#[cfg(feature = "postgres-sqlx")]
async fn save_postgres_key(
    connection: &mut PgConnection,
    mut key: RegistrationKey,
) -> Result<RegistrationKey> {
    if let Some(user) = key.user.take() {
        let user = save_postgres_user(connection, user).await?;
        key.key.user_id = user.row.id.to_string();
        key.user = Some(user);
    }
    let mut key = prepare_key(key)?;
    let (user_id, tags, created, expiry) = key_values(&key, SecondsFormat::Micros)?;
    let id = {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new("INSERT INTO pre_auth_keys (");
        if key.key.id != 0 {
            query.push("id,");
        }
        query.push(
            "key,prefix,hash,user_id,reusable,ephemeral,used,tags,created_at,expiration) VALUES (",
        );
        if key.key.id != 0 {
            query.push_bind(key.key.id).push(",");
        }
        query
            .push_bind(key.key.key.as_deref())
            .push(",")
            .push_bind(key.key.prefix.as_deref())
            .push(",")
            .push_bind(key.hash.as_deref())
            .push(",")
            .push_bind(user_id)
            .push(",")
            .push_bind(key.key.reusable)
            .push(",")
            .push_bind(key.key.ephemeral)
            .push(",")
            .push_bind(key.key.used_at.is_some())
            .push(",")
            .push_bind(tags.as_deref())
            .push(",")
            .push_bind(&created)
            .push("::TIMESTAMPTZ")
            .push(",")
            .push_bind(expiry.as_deref())
            .push("::TIMESTAMPTZ")
            .push(") ON CONFLICT DO NOTHING RETURNING id");
        query
            .build_query_scalar::<i64>()
            .fetch_optional(&mut *connection)
            .await?
    };
    if let Some(id) = id {
        key.key.id = id;
    }
    key.key.tags = tags.unwrap_or_else(|| "null".into());
    Ok(key)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_new_registration_with_associations(
    pool: &PgPool,
    node: NewNodeRegistration,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let mut transaction = pool.begin().await.map_err(saving_node)?;
    let saved = create_postgres_new_registration_with_associations_on_connection(
        &mut transaction,
        node,
        associations,
    )
    .await
    .map_err(saving_node)?;
    transaction.commit().await?;
    Ok(saved)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_new_registration_with_associations_on_connection(
    connection: &mut PgConnection,
    mut node: NewNodeRegistration,
    associations: NewNodeAssociations,
) -> Result<NewNodeSave> {
    let associations = save_postgres_associations(
        connection,
        &mut node.user_id,
        &mut node.auth_key_id,
        associations,
    )
    .await?;
    let node = super::create_postgres_new_registration_on_connection(connection, node).await?;
    Ok(NewNodeSave { node, associations })
}

pub(crate) async fn save_sqlite_associations(
    connection: &mut SqliteConnection,
    user_id: &mut Option<i64>,
    auth_key_id: &mut Option<i64>,
    associations: NewNodeAssociations,
) -> Result<NewNodeAssociations> {
    Ok(match associations {
        NewNodeAssociations::None => NewNodeAssociations::None,
        NewNodeAssociations::User(user) => {
            let user = save_sqlite_user(connection, *user).await?;
            *user_id = Some(user.row.id);
            NewNodeAssociations::User(Box::new(user))
        }
        NewNodeAssociations::AuthKey(key) => {
            let key = save_sqlite_key(connection, *key).await?;
            *auth_key_id = Some(key.key.id);
            if user_id.is_some()
                && let Some(user) = &key.user
            {
                *user_id = Some(user.row.id);
            }
            NewNodeAssociations::AuthKey(Box::new(key))
        }
    })
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) async fn save_postgres_associations(
    connection: &mut PgConnection,
    user_id: &mut Option<i64>,
    auth_key_id: &mut Option<i64>,
    associations: NewNodeAssociations,
) -> Result<NewNodeAssociations> {
    Ok(match associations {
        NewNodeAssociations::None => NewNodeAssociations::None,
        NewNodeAssociations::User(user) => {
            let user = save_postgres_user(connection, *user).await?;
            *user_id = Some(user.row.id);
            NewNodeAssociations::User(Box::new(user))
        }
        NewNodeAssociations::AuthKey(key) => {
            let key = save_postgres_key(connection, *key).await?;
            *auth_key_id = Some(key.key.id);
            if user_id.is_some()
                && let Some(user) = &key.user
            {
                *user_id = Some(user.row.id);
            }
            NewNodeAssociations::AuthKey(Box::new(key))
        }
    })
}
