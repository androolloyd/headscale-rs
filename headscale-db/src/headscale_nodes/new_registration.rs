// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Fresh State.createAndSaveNewNode persistence. SQL assigns the ID before
//! NodeStore resolves GivenName. Return the original typed node projection,
//! including pre-marshal Hostinfo and time precision, rather than a row reread.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};

use super::HeadscaleNodeRow;
use crate::{DbError, Result};

#[derive(Clone, Debug)]
pub struct NewNodeRegistration {
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    pub endpoints: Option<Vec<String>>,
    pub host_info: Option<Value>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    pub user_id: Option<i64>,
    pub register_method: String,
    pub tags: Option<Vec<String>>,
    pub auth_key_id: Option<i64>,
    pub expiry: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub approved_routes: Option<Vec<String>>,
}

struct Encoded {
    node: NewNodeRegistration,
    endpoints: Option<String>,
    host_info: Option<String>,
    tags: Option<String>,
    approved_routes: Option<String>,
}

impl NewNodeRegistration {
    fn encode(mut self) -> Result<Encoded> {
        use headscale_api_acl::go_key::PublicKeyKind;
        self.machine_key =
            crate::stored_text::key_for_write(&self.machine_key, PublicKeyKind::Machine)?;
        self.node_key = crate::stored_text::key_for_write(&self.node_key, PublicKeyKind::Node)?;
        self.disco_key = crate::stored_text::key_for_write(&self.disco_key, PublicKeyKind::Disco)?;
        self.ipv4 = crate::stored_text::optional_address(self.ipv4.as_deref())?;
        self.ipv6 = crate::stored_text::optional_address(self.ipv6.as_deref())?;
        if self.user_id.is_some_and(|id| id < 0) || self.auth_key_id.is_some_and(|id| id < 0) {
            return Err(DbError::General("invalid new node identity".into()));
        }
        if let Some(values) = &mut self.endpoints {
            *values = crate::stored_json::endpoint_values(values)?;
        }
        if let Some(values) = &mut self.approved_routes {
            *values = crate::stored_json::prefix_values(values)?;
        }
        let endpoints = self
            .endpoints
            .as_ref()
            .map(|values| super::json_array(values))
            .transpose()?;
        let host_info = self
            .host_info
            .as_ref()
            .map(super::host_info_for_write)
            .transpose()?
            .flatten();
        let tags = self
            .tags
            .as_ref()
            .map(|values| super::json_array(values))
            .transpose()?;
        let approved_routes = self
            .approved_routes
            .as_ref()
            .map(|values| super::json_array(values))
            .transpose()?;
        Ok(Encoded {
            node: self,
            endpoints,
            host_info,
            tags,
            approved_routes,
        })
    }

    fn initial_projection(self, id: i64, now: DateTime<Utc>) -> Result<HeadscaleNodeRow> {
        Ok(HeadscaleNodeRow {
            id,
            machine_key: self.machine_key,
            node_key: self.node_key,
            disco_key: self.disco_key,
            endpoints: serde_json::to_string(&self.endpoints)?,
            host_info: serde_json::to_string(&self.host_info)?,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            hostname: self.hostname,
            given_name: self.given_name,
            user_id: self.user_id,
            register_method: self.register_method,
            tags: serde_json::to_string(&self.tags)?,
            auth_key_id: self.auth_key_id,
            expiry: self.expiry.map(|value| value.timestamp()),
            expiry_text: self
                .expiry
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true)),
            last_seen: self.last_seen.map(|value| value.timestamp()),
            last_seen_text: self
                .last_seen
                .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true)),
            approved_routes: serde_json::to_string(&self.approved_routes)?,
            created_at: now.timestamp(),
            created_at_text: now.to_rfc3339_opts(SecondsFormat::Nanos, true),
            updated_at: now.timestamp(),
            deleted_at: None,
        })
    }
}

pub async fn create_new_registration(
    pool: &SqlitePool,
    node: NewNodeRegistration,
) -> Result<HeadscaleNodeRow> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let node = create_new_registration_on_connection(&mut tx, node).await?;
    tx.commit().await?;
    Ok(node)
}

pub async fn create_new_registration_on_connection(
    connection: &mut SqliteConnection,
    node: NewNodeRegistration,
) -> Result<HeadscaleNodeRow> {
    let values = node.encode()?;
    let node = &values.node;
    let now = Utc::now();
    let clock = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let expiry = node
        .expiry
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    let last_seen = node
        .last_seen
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    let id: i64 = sqlx::query_scalar("INSERT INTO nodes (machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, expiry, last_seen, approved_routes, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) RETURNING id")
        .bind(&node.machine_key).bind(&node.node_key).bind(&node.disco_key)
        .bind(values.endpoints.as_deref()).bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref()).bind(node.ipv6.as_deref())
        .bind(&node.hostname).bind(&node.given_name).bind(node.user_id)
        .bind(&node.register_method).bind(values.tags.as_deref()).bind(node.auth_key_id)
        .bind(expiry).bind(last_seen).bind(values.approved_routes.as_deref())
        .bind(&clock).bind(&clock).fetch_one(connection).await.map_err(crate::DbError::from)?;
    values.node.initial_projection(id, now)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_new_registration(
    pool: &PgPool,
    node: NewNodeRegistration,
) -> Result<HeadscaleNodeRow> {
    let mut tx = pool.begin().await?;
    let node = create_postgres_new_registration_on_connection(&mut tx, node).await?;
    tx.commit().await?;
    Ok(node)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_new_registration_on_connection(
    connection: &mut PgConnection,
    node: NewNodeRegistration,
) -> Result<HeadscaleNodeRow> {
    let values = node.encode()?;
    let node = &values.node;
    let now = Utc::now();
    let clock = now.to_rfc3339_opts(SecondsFormat::Micros, true);
    let expiry = node
        .expiry
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let last_seen = node
        .last_seen
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let id: i64 = sqlx::query_scalar("INSERT INTO nodes (machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, expiry, last_seen, approved_routes, created_at, updated_at, deleted_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::TIMESTAMPTZ, $15::TIMESTAMPTZ, $16, $17::TIMESTAMPTZ, $18::TIMESTAMPTZ, NULL) RETURNING id")
        .bind(&node.machine_key).bind(&node.node_key).bind(&node.disco_key)
        .bind(values.endpoints.as_deref()).bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref()).bind(node.ipv6.as_deref())
        .bind(&node.hostname).bind(&node.given_name).bind(node.user_id)
        .bind(&node.register_method).bind(values.tags.as_deref()).bind(node.auth_key_id)
        .bind(expiry).bind(last_seen).bind(values.approved_routes.as_deref())
        .bind(&clock).bind(&clock).fetch_one(connection).await.map_err(crate::DbError::from)?;
    values.node.initial_projection(id, now)
}
