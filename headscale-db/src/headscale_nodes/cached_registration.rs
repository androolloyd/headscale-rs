// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Existing-node auth saves use the current NodeStore column values. They do
//! not insert missing rows, reserve names in SQL, or rewrite creation/deletion
//! timestamps. Auth-key reauth writes AuthKeyID; web reauth omits it unless nil.

use chrono::{DateTime, SecondsFormat, Utc};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};

use super::CachedNodeSnapshot;
use crate::Result;

#[derive(Clone, Copy, Debug)]
pub enum RegistrationAuthKey {
    Preserve,
    Set(Option<i64>),
}

#[derive(Clone, Debug)]
pub struct CachedNodeRegistration {
    pub node: CachedNodeSnapshot,
    pub expiry: Option<DateTime<Utc>>,
    pub auth_key: RegistrationAuthKey,
}

pub async fn save_cached_registration(
    pool: &SqlitePool,
    registration: CachedNodeRegistration,
) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    save_cached_registration_on_connection(&mut tx, registration).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn save_cached_registration_on_connection(
    connection: &mut SqliteConnection,
    registration: CachedNodeRegistration,
) -> Result<()> {
    let values = registration.node.encode()?;
    let node = &values.node;
    let last_seen = node
        .last_seen
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    let expiry = registration
        .expiry
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    let sql = match registration.auth_key {
        RegistrationAuthKey::Preserve => {
            "UPDATE nodes SET machine_key = ?, node_key = ?, disco_key = ?, endpoints = ?, host_info = ?, ipv4 = ?, ipv6 = ?, hostname = ?, given_name = ?, user_id = ?, register_method = ?, tags = ?, last_seen = ?, approved_routes = ?, expiry = ?, updated_at = ? WHERE id = ?"
        }
        RegistrationAuthKey::Set(_) => {
            "UPDATE nodes SET machine_key = ?, node_key = ?, disco_key = ?, endpoints = ?, host_info = ?, ipv4 = ?, ipv6 = ?, hostname = ?, given_name = ?, user_id = ?, register_method = ?, tags = ?, last_seen = ?, approved_routes = ?, expiry = ?, updated_at = ?, auth_key_id = ? WHERE id = ?"
        }
    };
    let mut query = sqlx::query(sql)
        .bind(&node.machine_key)
        .bind(&node.node_key)
        .bind(&node.disco_key)
        .bind(values.endpoints.as_deref())
        .bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref())
        .bind(node.ipv6.as_deref())
        .bind(&node.hostname)
        .bind(&node.given_name)
        .bind(node.user_id)
        .bind(&node.register_method)
        .bind(values.tags.as_deref())
        .bind(last_seen)
        .bind(values.approved_routes.as_deref())
        .bind(expiry)
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true));
    if let RegistrationAuthKey::Set(id) = registration.auth_key {
        query = query.bind(id);
    }
    query
        .bind(node.id)
        .execute(connection)
        .await
        .map_err(crate::DbError::from)?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn save_postgres_cached_registration(
    pool: &PgPool,
    registration: CachedNodeRegistration,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    save_postgres_cached_registration_on_connection(&mut tx, registration).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn save_postgres_cached_registration_on_connection(
    connection: &mut PgConnection,
    registration: CachedNodeRegistration,
) -> Result<()> {
    let values = registration.node.encode()?;
    let node = &values.node;
    let last_seen = node
        .last_seen
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let expiry = registration
        .expiry
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let sql = match registration.auth_key {
        RegistrationAuthKey::Preserve => {
            "UPDATE nodes SET machine_key = $1, node_key = $2, disco_key = $3, endpoints = $4, host_info = $5, ipv4 = $6, ipv6 = $7, hostname = $8, given_name = $9, user_id = $10, register_method = $11, tags = $12, last_seen = $13::TIMESTAMPTZ, approved_routes = $14, expiry = $15::TIMESTAMPTZ, updated_at = $16::TIMESTAMPTZ WHERE id = $17"
        }
        RegistrationAuthKey::Set(_) => {
            "UPDATE nodes SET machine_key = $1, node_key = $2, disco_key = $3, endpoints = $4, host_info = $5, ipv4 = $6, ipv6 = $7, hostname = $8, given_name = $9, user_id = $10, register_method = $11, tags = $12, last_seen = $13::TIMESTAMPTZ, approved_routes = $14, expiry = $15::TIMESTAMPTZ, updated_at = $16::TIMESTAMPTZ, auth_key_id = $17 WHERE id = $18"
        }
    };
    let mut query = sqlx::query(sql)
        .bind(&node.machine_key)
        .bind(&node.node_key)
        .bind(&node.disco_key)
        .bind(values.endpoints.as_deref())
        .bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref())
        .bind(node.ipv6.as_deref())
        .bind(&node.hostname)
        .bind(&node.given_name)
        .bind(node.user_id)
        .bind(&node.register_method)
        .bind(values.tags.as_deref())
        .bind(last_seen)
        .bind(values.approved_routes.as_deref())
        .bind(expiry)
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true));
    if let RegistrationAuthKey::Set(id) = registration.auth_key {
        query = query.bind(id);
    }
    query
        .bind(node.id)
        .execute(connection)
        .await
        .map_err(crate::DbError::from)?;
    Ok(())
}
