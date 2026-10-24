// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause
// headscale-go v0.29.5 db/api_key.go and Gorm v1.31.1 callbacks.
// See UPSTREAM.md and retained upstream licenses.

//! State API-key saves retain the original model and separate lookup from
//! mutation. A successful zero-row write after that lookup is not an error.

use super::{ApiKeyRow, CreateParams, Created};
use crate::{DbError, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::SqlitePool;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{Connection, PgConnection, PgPool};

pub(super) struct PreparedKey {
    plaintext: String,
    prefix: String,
    secret_hash: String,
    expiration: Option<DateTime<Utc>>,
}

pub(super) fn saving_error(error: impl Into<DbError>) -> DbError {
    DbError::General(format!(
        "saving API key to database: {}",
        error.into().headscale_go_message()
    ))
}

pub(super) async fn prepare(
    params: CreateParams,
    cost: u32,
    expiration: Option<DateTime<Utc>>,
) -> Result<PreparedKey> {
    let (plaintext, prefix, secret) = super::try_generate_plaintext()?;
    let secret_hash = crate::credential_hash::hash(secret, cost)
        .await
        .map_err(DbError::General)?;
    Ok(PreparedKey {
        plaintext,
        prefix,
        secret_hash,
        expiration: expiration.or_else(|| {
            params
                .expiration
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        }),
    })
}

impl PreparedKey {
    fn into_created(self, id: i64, created_at: DateTime<Utc>) -> Created {
        Created {
            plaintext: self.plaintext,
            row: ApiKeyRow {
                id,
                prefix: self.prefix,
                secret_hash: self.secret_hash,
                expiration: self.expiration.map(|value| value.timestamp()),
                expiration_text: self
                    .expiration
                    .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true)),
                created_at: created_at.timestamp(),
                created_at_text: Some(created_at.to_rfc3339_opts(SecondsFormat::Nanos, true)),
                last_seen: None,
                last_seen_text: None,
            },
        }
    }
}

pub(super) async fn create(pool: &SqlitePool, key: PreparedKey) -> Result<Created> {
    let mut transaction = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(saving_error)?;
    // Gorm assigns CreatedAt in its create callback after beginning the save.
    let created_at = Utc::now();
    let expiration = key
        .expiration
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    // Gorm create scans RETURNING without RaiseErrorOnNotFound. A trigger
    // suppressing the insert leaves the original zero ID and is not a lookup
    // failure; no later row read is invented here.
    let id = sqlx::query_scalar("INSERT INTO api_keys (prefix, hash, expiration, created_at, last_seen) VALUES (?, ?, ?, ?, NULL) RETURNING id")
        .bind(&key.prefix)
        .bind(key.secret_hash.as_bytes())
        .bind(expiration)
        .bind(created_at.to_rfc3339_opts(SecondsFormat::Nanos, true))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(saving_error)?
        .unwrap_or_default();
    transaction.commit().await.map_err(saving_error)?;
    Ok(key.into_created(id, created_at))
}

#[cfg(feature = "postgres-sqlx")]
pub(super) async fn create_postgres(conn: &mut PgConnection, key: PreparedKey) -> Result<Created> {
    let mut transaction = conn.begin().await.map_err(saving_error)?;
    let created_at = Utc::now();
    let expiration = key
        .expiration
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let id = sqlx::query_scalar("INSERT INTO api_keys (prefix, hash, expiration, created_at, last_seen) VALUES ($1, $2, $3::TIMESTAMPTZ, $4::TIMESTAMPTZ, NULL) RETURNING id")
        .bind(&key.prefix)
        .bind(key.secret_hash.as_bytes())
        .bind(expiration)
        .bind(created_at.to_rfc3339_opts(SecondsFormat::Micros, true))
        .fetch_optional(&mut *transaction)
        .await
        .map_err(saving_error)?
        .unwrap_or_default();
    transaction.commit().await.map_err(saving_error)?;
    // The driver binding truncates to micros, but the returned Go model keeps
    // its original nanos. Triggers/rounded values are not read back into it.
    Ok(key.into_created(id, created_at))
}

pub async fn list_for_state(pool: &SqlitePool) -> Result<Vec<ApiKeyRow>> {
    Ok(sqlx::query_as(&super::api_key_select(""))
        .fetch_all(pool)
        .await?)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_for_state(pool: &PgPool) -> Result<Vec<ApiKeyRow>> {
    Ok(sqlx::query_as(&super::postgres_api_key_select(""))
        .fetch_all(pool)
        .await?)
}

fn require_primary_key(key: &ApiKeyRow) -> Result<()> {
    if key.id == 0 {
        return Err(DbError::General("WHERE conditions required".into()));
    }
    Ok(())
}

pub(super) async fn expire(pool: &SqlitePool, key: &ApiKeyRow) -> Result<()> {
    // db.ExpireAPIKey evaluates time.Now before entering Update's callbacks.
    let expiration = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    require_primary_key(key)?;
    sqlx::query("UPDATE api_keys SET expiration = ? WHERE id = ?")
        .bind(expiration)
        .bind(key.id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

pub(super) async fn destroy(pool: &SqlitePool, key: &ApiKeyRow) -> Result<()> {
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    require_primary_key(key)?;
    sqlx::query("DELETE FROM api_keys WHERE id = ?")
        .bind(key.id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub(super) async fn expire_postgres(conn: &mut PgConnection, key: &ApiKeyRow) -> Result<()> {
    expire_postgres_at(conn, key, Utc::now()).await
}

#[cfg(feature = "postgres-sqlx")]
pub(super) async fn expire_postgres_at(
    conn: &mut PgConnection,
    key: &ApiKeyRow,
    expiration: DateTime<Utc>,
) -> Result<()> {
    let expiration = expiration.to_rfc3339_opts(SecondsFormat::Micros, true);
    let mut transaction = conn.begin().await?;
    require_primary_key(key)?;
    sqlx::query("UPDATE api_keys SET expiration = $1::TIMESTAMPTZ WHERE id = $2")
        .bind(expiration)
        .bind(key.id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub(super) async fn destroy_postgres(conn: &mut PgConnection, key: &ApiKeyRow) -> Result<()> {
    let mut transaction = conn.begin().await?;
    require_primary_key(key)?;
    sqlx::query("DELETE FROM api_keys WHERE id = $1")
        .bind(key.id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}
