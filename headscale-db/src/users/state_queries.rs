// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause
// State.ListUsersWithFilter/db.ListUsers at headscale-go v0.29.5.
// See UPSTREAM.md and retained upstream licenses.

//! User listing loads every matching model, without unique-name lookup or
//! display-name fallback. The RPC selects one filter and sorts its response.

use super::UserRow;
use crate::Result;

#[derive(Clone, Copy, Debug)]
pub enum UserListFilter<'a> {
    All,
    Name(&'a str),
    Email(&'a str),
    Id(i64),
}

pub async fn list_for_state(
    pool: &sqlx::SqlitePool,
    filter: UserListFilter<'_>,
) -> Result<Vec<UserRow>> {
    let mut query =
        sqlx::QueryBuilder::<sqlx::Sqlite>::new(super::user_select("WHERE deleted_at IS NULL"));
    // A zero struct-WHERE field contributes no condition in Gorm.
    match filter {
        UserListFilter::Name(name) if !name.is_empty() => {
            query.push(" AND name = ").push_bind(name);
        }
        UserListFilter::Email(email) if !email.is_empty() => {
            query.push(" AND email = ").push_bind(email);
        }
        UserListFilter::Id(id) if id != 0 => {
            query.push(" AND id = ").push_bind(id);
        }
        _ => {}
    }
    Ok(query.build_query_as::<UserRow>().fetch_all(pool).await?)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_for_state(
    pool: &sqlx::PgPool,
    filter: UserListFilter<'_>,
) -> Result<Vec<UserRow>> {
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(super::postgres_user_select(
        "WHERE deleted_at IS NULL",
    ));
    match filter {
        UserListFilter::Name(name) if !name.is_empty() => {
            query.push(" AND name = ").push_bind(name);
        }
        UserListFilter::Email(email) if !email.is_empty() => {
            query.push(" AND email = ").push_bind(email);
        }
        UserListFilter::Id(id) if id != 0 => {
            query.push(" AND id = ").push_bind(id);
        }
        _ => {}
    }
    Ok(query.build_query_as::<UserRow>().fetch_all(pool).await?)
}
