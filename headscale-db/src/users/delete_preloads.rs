// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause
// DestroyUser/ListNodesByUser/ListPreAuthKeysByUser at headscale-go v0.29.5
// and Gorm v1.31.1 preload ordering. See UPSTREAM.md and retained licenses.

//! The read phases of Go DestroyUser, on the caller's write connection.
//!
//! Counts and ID-only queries would hide model scan/preload failures. Gorm
//! loads nodes, AuthKey, AuthKey.User and User before the ownership decision,
//! then loads the user's keys and their User association before deleting keys.

use crate::headscale_nodes::HeadscaleNodeRow;
use crate::preauth_keys::{PreauthKeyRow, association_user_ids};
use crate::{DbError, Result};
use std::collections::BTreeSet;

fn auth_key_ids(nodes: &[HeadscaleNodeRow]) -> BTreeSet<i64> {
    // A non-nil FK pointer containing zero is still a Gorm preload identity.
    nodes.iter().filter_map(|node| node.auth_key_id).collect()
}

fn node_user_ids(nodes: &[HeadscaleNodeRow]) -> Vec<i64> {
    nodes
        .iter()
        .filter_map(|node| node.user_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) async fn load_keys_for_deletion(
    conn: &mut sqlx::SqliteConnection,
    id: i64,
) -> Result<Vec<PreauthKeyRow>> {
    // Node.DeletedAt is a plain timestamp, so it does not soft-delete nodes.
    let query = crate::headscale_nodes::node_select("WHERE user_id = ?");
    let nodes = sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;

    // Gorm sorts association names: AuthKey (including nested User), then User.
    let key_ids = auth_key_ids(&nodes);
    if !key_ids.is_empty() {
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            crate::preauth_keys::preauth_key_select("WHERE id IN ("),
        );
        let mut values = query.separated(", ");
        for key_id in key_ids {
            values.push_bind(key_id);
        }
        values.push_unseparated(")");
        let keys = query
            .build_query_as::<PreauthKeyRow>()
            .fetch_all(&mut *conn)
            .await?;
        super::list_by_ids_on_connection(conn, &association_user_ids(&keys)?).await?;
    }
    super::list_by_ids_on_connection(conn, &node_user_ids(&nodes)).await?;

    if !nodes.is_empty() {
        return Err(DbError::Constraint("user not empty: node(s) found".into()));
    }

    let query = crate::preauth_keys::preauth_key_select("WHERE user_id = ?");
    let keys = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;
    // Missing or soft-deleted associated users are nil, not a lookup error.
    super::list_by_ids_on_connection(conn, &association_user_ids(&keys)?).await?;
    Ok(keys)
}

#[cfg(feature = "postgres-sqlx")]
pub(super) async fn load_postgres_keys_for_deletion(
    conn: &mut sqlx::PgConnection,
    id: i64,
) -> Result<Vec<PreauthKeyRow>> {
    let query = crate::headscale_nodes::postgres_node_select("WHERE user_id = $1");
    let nodes = sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;

    let key_ids = auth_key_ids(&nodes);
    if !key_ids.is_empty() {
        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            crate::preauth_keys::postgres_preauth_key_select("WHERE id IN ("),
        );
        let mut values = query.separated(", ");
        for key_id in key_ids {
            values.push_bind(key_id);
        }
        values.push_unseparated(")");
        let keys = query
            .build_query_as::<PreauthKeyRow>()
            .fetch_all(&mut *conn)
            .await?;
        super::list_postgres_by_ids_on_connection(conn, &association_user_ids(&keys)?).await?;
    }
    super::list_postgres_by_ids_on_connection(conn, &node_user_ids(&nodes)).await?;

    if !nodes.is_empty() {
        return Err(DbError::Constraint("user not empty: node(s) found".into()));
    }

    let query = crate::preauth_keys::postgres_preauth_key_select("WHERE user_id = $1");
    let keys = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;
    super::list_postgres_by_ids_on_connection(conn, &association_user_ids(&keys)?).await?;
    Ok(keys)
}
