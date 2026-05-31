//! Headscale-go-compatible node persistence.
//!
//! This module owns the canonical `nodes` table that mirrors
//! `juanfont/headscale@v0.28.0:hscontrol/types/node.go`. Octra's
//! mesh-oriented node store remains in [`crate::nodes`] and persists to
//! `octra_nodes`, so Octra-specific shape does not occupy the upstream
//! table name.

use crate::{DbError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqlitePool;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};

pub const REGISTER_METHOD_AUTH_KEY: &str = "authkey";
pub const REGISTER_METHOD_CLI: &str = "cli";
pub const REGISTER_METHOD_OIDC: &str = "oidc";

const NODE_COLUMNS: &str = r"
        id,
        COALESCE(machine_key, '') AS machine_key,
        COALESCE(node_key, '') AS node_key,
        COALESCE(disco_key, '') AS disco_key,
        COALESCE(endpoints, '[]') AS endpoints,
        COALESCE(host_info, '{}') AS host_info,
        ipv4,
        ipv6,
        COALESCE(hostname, '') AS hostname,
        COALESCE(given_name, '') AS given_name,
        user_id,
        COALESCE(register_method, '') AS register_method,
        COALESCE(tags, '[]') AS tags,
        auth_key_id,
        CASE
            WHEN expiry IS NULL THEN NULL
            WHEN typeof(expiry) = 'integer' THEN expiry
            WHEN CAST(expiry AS TEXT) LIKE '0001-01-01%' THEN NULL
            ELSE unixepoch(expiry)
        END AS expiry,
        CASE
            WHEN last_seen IS NULL THEN NULL
            WHEN typeof(last_seen) = 'integer' THEN last_seen
            ELSE unixepoch(last_seen)
        END AS last_seen,
        COALESCE(approved_routes, '[]') AS approved_routes,
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

fn node_select(suffix: &str) -> String {
    format!("SELECT {NODE_COLUMNS} FROM nodes {suffix}")
}

fn sqlite_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(", ")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_NODE_COLUMNS: &str = r"
        id,
        COALESCE(machine_key, '') AS machine_key,
        COALESCE(node_key, '') AS node_key,
        COALESCE(disco_key, '') AS disco_key,
        COALESCE(endpoints, '[]') AS endpoints,
        COALESCE(host_info, '{}') AS host_info,
        ipv4,
        ipv6,
        COALESCE(hostname, '') AS hostname,
        COALESCE(given_name, '') AS given_name,
        user_id,
        COALESCE(register_method, '') AS register_method,
        COALESCE(tags, '[]') AS tags,
        auth_key_id,
        FLOOR(EXTRACT(EPOCH FROM expiry))::BIGINT AS expiry,
        FLOOR(EXTRACT(EPOCH FROM last_seen))::BIGINT AS last_seen,
        COALESCE(approved_routes, '[]') AS approved_routes,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM updated_at))::BIGINT, 0) AS updated_at,
        FLOOR(EXTRACT(EPOCH FROM deleted_at))::BIGINT AS deleted_at
";

#[cfg(feature = "postgres-sqlx")]
fn postgres_node_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_NODE_COLUMNS} FROM nodes {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadscaleNodeRow {
    pub id: i64,
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    pub endpoints: String,
    pub host_info: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    pub user_id: Option<i64>,
    pub register_method: String,
    pub tags: String,
    pub auth_key_id: Option<i64>,
    pub expiry: Option<i64>,
    pub last_seen: Option<i64>,
    pub approved_routes: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

impl HeadscaleNodeRow {
    pub fn endpoint_list(&self) -> Vec<String> {
        serde_json::from_str(&self.endpoints).unwrap_or_default()
    }

    pub fn host_info_value(&self) -> Value {
        serde_json::from_str(&self.host_info).unwrap_or_else(|_| json!({}))
    }

    pub fn tag_list(&self) -> Vec<String> {
        serde_json::from_str(&self.tags).unwrap_or_default()
    }

    pub fn approved_route_list(&self) -> Vec<String> {
        serde_json::from_str(&self.approved_routes).unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct CreateParams {
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    pub endpoints: Vec<String>,
    pub host_info: Value,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    pub user_id: Option<i64>,
    pub register_method: String,
    pub tags: Vec<String>,
    pub auth_key_id: Option<i64>,
    pub expiry: Option<i64>,
    pub last_seen: Option<i64>,
    pub approved_routes: Vec<String>,
}

impl Default for CreateParams {
    fn default() -> Self {
        Self {
            machine_key: String::new(),
            node_key: String::new(),
            disco_key: String::new(),
            endpoints: Vec::new(),
            host_info: json!({}),
            ipv4: None,
            ipv6: None,
            hostname: String::new(),
            given_name: String::new(),
            user_id: None,
            register_method: REGISTER_METHOD_AUTH_KEY.to_string(),
            tags: Vec::new(),
            auth_key_id: None,
            expiry: None,
            last_seen: None,
            approved_routes: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NodeError {
    #[error("node already exists")]
    Exists,
    #[error("node not found")]
    NotFound,
    #[error("name is not unique")]
    NameNotUnique,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn json_array(values: &[String]) -> Result<String> {
    Ok(serde_json::to_string(values)?)
}

fn json_object_or_value(value: &Value) -> Result<String> {
    if value.is_null() {
        Ok("{}".to_string())
    } else {
        Ok(serde_json::to_string(value)?)
    }
}

fn normalize_tags(mut tags: Vec<String>) -> Vec<String> {
    tags.sort();
    tags.dedup();
    tags
}

fn tag_owned_user_id(user_id: Option<i64>, tags: &[String]) -> Option<i64> {
    if tags.is_empty() { user_id } else { None }
}

fn expand_exit_routes(mut routes: Vec<String>) -> Vec<String> {
    let has_ipv4_exit = routes.iter().any(|route| route == "0.0.0.0/0");
    let has_ipv6_exit = routes.iter().any(|route| route == "::/0");
    match (has_ipv4_exit, has_ipv6_exit) {
        (true, false) => routes.push("::/0".to_string()),
        (false, true) => routes.push("0.0.0.0/0".to_string()),
        _ => {}
    }
    routes
}

fn is_dns_label_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_dns_label_char(byte: u8) -> bool {
    is_dns_label_alphanumeric(byte) || byte == b'-'
}

fn validate_given_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(DbError::General("empty DNS label".into()));
    }
    if bytes.len() > 63 {
        return Err(DbError::General(format!(
            "{name:?} is too long, max length is 63 bytes"
        )));
    }
    if !is_dns_label_alphanumeric(bytes[0]) {
        return Err(DbError::General(format!(
            "{name:?} is not a valid DNS label: must start with a letter or number"
        )));
    }
    if !is_dns_label_alphanumeric(bytes[bytes.len() - 1]) {
        return Err(DbError::General(format!(
            "{name:?} is not a valid DNS label: must end with a letter or number"
        )));
    }
    if bytes.len() > 2 {
        for byte in &bytes[1..bytes.len() - 1] {
            if !is_dns_label_char(*byte) {
                return Err(DbError::General(format!(
                    "{name:?} is not a valid DNS label: contains invalid character {:?}",
                    char::from(*byte)
                )));
            }
        }
    }
    Ok(())
}

fn sanitize_hostname_for_given_name(hostname: &str) -> String {
    let hostname = hostname.strip_suffix(".local").unwrap_or(hostname);
    let hostname = hostname.strip_suffix(".localdomain").unwrap_or(hostname);
    let hostname = hostname.strip_suffix(".lan").unwrap_or(hostname);
    let bytes = hostname.as_bytes();
    let mut start = 0usize;
    let mut end = bytes.len().min(63);

    while start < end && !is_dns_label_alphanumeric(bytes[start]) {
        start += 1;
    }
    while start < end && !is_dns_label_alphanumeric(bytes[end - 1]) {
        end -= 1;
    }

    let mut out = String::with_capacity(end.saturating_sub(start));
    for (offset, byte) in bytes[start..end].iter().enumerate() {
        let absolute = start + offset;
        let boundary = absolute == start || absolute == end - 1;
        match *byte {
            b' ' | b'.' | b'@' | b'_' if !boundary => out.push('-'),
            b'a'..=b'z' | b'0'..=b'9' | b'-' => out.push(char::from(*byte)),
            b'A'..=b'Z' => out.push(char::from(byte.to_ascii_lowercase())),
            _ => {}
        }
    }
    out
}

fn auto_given_name_base(hostname: &str) -> String {
    let sanitized = sanitize_hostname_for_given_name(hostname);
    if sanitized.is_empty() {
        "node".to_string()
    } else {
        sanitized
    }
}

fn resolve_given_name_from_existing<I>(base: &str, existing: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let taken = existing
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    let mut candidate = base.to_string();
    for suffix in 1.. {
        if !taken.contains(&candidate) {
            return candidate;
        }
        candidate = format!("{base}-{suffix}");
    }
    unreachable!("unbounded suffix search always returns")
}

async fn resolve_auto_given_name(
    pool: &SqlitePool,
    self_id: Option<i64>,
    hostname: &str,
) -> Result<String> {
    let base = auto_given_name_base(hostname);
    let rows: Vec<String> = sqlx::query_scalar(
        "
        SELECT given_name
        FROM nodes
        WHERE deleted_at IS NULL
          AND given_name IS NOT NULL
          AND given_name != ''
          AND (? IS NULL OR id != ?)
        ",
    )
    .bind(self_id)
    .bind(self_id)
    .fetch_all(pool)
    .await?;
    Ok(resolve_given_name_from_existing(&base, rows))
}

#[cfg(feature = "postgres-sqlx")]
async fn resolve_postgres_auto_given_name(
    conn: &mut PgConnection,
    self_id: Option<i64>,
    hostname: &str,
) -> Result<String> {
    let base = auto_given_name_base(hostname);
    let rows: Vec<String> = sqlx::query_scalar(
        "
        SELECT given_name
        FROM nodes
        WHERE deleted_at IS NULL
          AND given_name IS NOT NULL
          AND given_name != ''
          AND ($1::BIGINT IS NULL OR id != $1)
        ",
    )
    .bind(self_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(resolve_given_name_from_existing(&base, rows))
}

async fn create_given_name(pool: &SqlitePool, params: &CreateParams) -> Result<String> {
    if params.given_name.is_empty() {
        resolve_auto_given_name(pool, None, &params.hostname).await
    } else {
        validate_given_name(&params.given_name)?;
        Ok(params.given_name.clone())
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn create_postgres_given_name(
    conn: &mut PgConnection,
    params: &CreateParams,
) -> Result<String> {
    if params.given_name.is_empty() {
        resolve_postgres_auto_given_name(conn, None, &params.hostname).await
    } else {
        validate_given_name(&params.given_name)?;
        Ok(params.given_name.clone())
    }
}

async fn auth_path_given_name(pool: &SqlitePool, id: i64, params: &CreateParams) -> Result<String> {
    if params.given_name.is_empty() {
        return resolve_auto_given_name(pool, Some(id), &params.hostname).await;
    }

    validate_given_name(&params.given_name)?;
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM nodes
        WHERE given_name = ? AND id != ? AND deleted_at IS NULL
        ",
    )
    .bind(&params.given_name)
    .bind(id)
    .fetch_one(pool)
    .await?;
    if count > 0 {
        return Err(DbError::General(NodeError::NameNotUnique.to_string()));
    }
    Ok(params.given_name.clone())
}

#[cfg(feature = "postgres-sqlx")]
async fn auth_path_postgres_given_name(
    conn: &mut PgConnection,
    id: i64,
    params: &CreateParams,
) -> Result<String> {
    if params.given_name.is_empty() {
        return resolve_postgres_auto_given_name(conn, Some(id), &params.hostname).await;
    }

    validate_given_name(&params.given_name)?;
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM nodes
        WHERE given_name = $1 AND id != $2 AND deleted_at IS NULL
        ",
    )
    .bind(&params.given_name)
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if count > 0 {
        return Err(DbError::General(NodeError::NameNotUnique.to_string()));
    }
    Ok(params.given_name.clone())
}

pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<HeadscaleNodeRow> {
    let given_name = create_given_name(pool, &params).await?;

    let now = now_unix();
    let tags = normalize_tags(params.tags);
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&expand_exit_routes(params.approved_routes))?;

    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO nodes (
            machine_key,
            node_key,
            disco_key,
            endpoints,
            host_info,
            ipv4,
            ipv6,
            hostname,
            given_name,
            user_id,
            register_method,
            tags,
            auth_key_id,
            expiry,
            last_seen,
            approved_routes,
            created_at,
            updated_at,
            deleted_at
        )
        VALUES (
            NULLIF(?, ''),
            NULLIF(?, ''),
            NULLIF(?, ''),
            ?,
            ?,
            ?,
            ?,
            NULLIF(?, ''),
            NULLIF(?, ''),
            ?,
            NULLIF(?, ''),
            ?,
            ?,
            CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            ?,
            datetime(?, 'unixepoch'),
            datetime(?, 'unixepoch'),
            NULL
        )
        RETURNING id
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(&host_info)
    .bind(&params.ipv4)
    .bind(&params.ipv6)
    .bind(&params.hostname)
    .bind(&given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(params.expiry)
    .bind(params.expiry)
    .bind(params.last_seen)
    .bind(params.last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(map_sqlx_err)?;

    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres(pool: &PgPool, params: CreateParams) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    create_postgres_on_connection(&mut conn, params).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    let given_name = create_postgres_given_name(conn, &params).await?;

    let now = now_unix();
    let tags = normalize_tags(params.tags);
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&expand_exit_routes(params.approved_routes))?;

    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO nodes (
            machine_key,
            node_key,
            disco_key,
            endpoints,
            host_info,
            ipv4,
            ipv6,
            hostname,
            given_name,
            user_id,
            register_method,
            tags,
            auth_key_id,
            expiry,
            last_seen,
            approved_routes,
            created_at,
            updated_at,
            deleted_at
        )
        VALUES (
            NULLIF($1, ''),
            NULLIF($2, ''),
            NULLIF($3, ''),
            $4,
            $5,
            $6,
            $7,
            NULLIF($8, ''),
            NULLIF($9, ''),
            $10,
            NULLIF($11, ''),
            $12,
            $13,
            CASE
                WHEN $14::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($14::BIGINT)::DOUBLE PRECISION)
            END,
            CASE
                WHEN $15::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($15::BIGINT)::DOUBLE PRECISION)
            END,
            $16,
            to_timestamp(($17::BIGINT)::DOUBLE PRECISION),
            to_timestamp(($18::BIGINT)::DOUBLE PRECISION),
            NULL
        )
        RETURNING id
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(&host_info)
    .bind(&params.ipv4)
    .bind(&params.ipv6)
    .bind(&params.hostname)
    .bind(&given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(params.expiry)
    .bind(params.last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *conn)
    .await
    .map_err(map_sqlx_err)?;

    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<HeadscaleNodeRow> {
    let query = node_select("WHERE id = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_node_key(pool: &SqlitePool, node_key: &str) -> Result<HeadscaleNodeRow> {
    let query = node_select("WHERE node_key = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(node_key)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_machine_key(pool: &SqlitePool, machine_key: &str) -> Result<HeadscaleNodeRow> {
    let query = node_select("WHERE machine_key = ? AND deleted_at IS NULL ORDER BY id LIMIT 1");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_machine_key_and_user(
    pool: &SqlitePool,
    machine_key: &str,
    user_id: i64,
) -> Result<HeadscaleNodeRow> {
    let query = node_select(
        "WHERE machine_key = ? AND user_id = ? AND deleted_at IS NULL ORDER BY id LIMIT 1",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_user_hostname(
    pool: &SqlitePool,
    user_id: i64,
    hostname: &str,
) -> Result<HeadscaleNodeRow> {
    let query = node_select(
        "WHERE user_id = ? AND hostname = ? AND deleted_at IS NULL ORDER BY id LIMIT 1",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(user_id)
        .bind(hostname)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id(pool: &PgPool, id: i64) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_id_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<HeadscaleNodeRow> {
    let query = postgres_node_select("WHERE id = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_node_key(pool: &PgPool, node_key: &str) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_node_key_on_connection(&mut conn, node_key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_node_key_on_connection(
    conn: &mut PgConnection,
    node_key: &str,
) -> Result<HeadscaleNodeRow> {
    let query = postgres_node_select("WHERE node_key = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(node_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_machine_key(
    pool: &PgPool,
    machine_key: &str,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_machine_key_on_connection(&mut conn, machine_key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_machine_key_on_connection(
    conn: &mut PgConnection,
    machine_key: &str,
) -> Result<HeadscaleNodeRow> {
    let query =
        postgres_node_select("WHERE machine_key = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_machine_key_and_user(
    pool: &PgPool,
    machine_key: &str,
    user_id: i64,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_machine_key_and_user_on_connection(&mut conn, machine_key, user_id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_machine_key_and_user_on_connection(
    conn: &mut PgConnection,
    machine_key: &str,
    user_id: i64,
) -> Result<HeadscaleNodeRow> {
    let query = postgres_node_select(
        "WHERE machine_key = $1 AND user_id = $2 AND deleted_at IS NULL ORDER BY id LIMIT 1",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_user_hostname(
    pool: &PgPool,
    user_id: i64,
    hostname: &str,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_user_hostname_on_connection(&mut conn, user_id, hostname).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_user_hostname_on_connection(
    conn: &mut PgConnection,
    user_id: i64,
    hostname: &str,
) -> Result<HeadscaleNodeRow> {
    let query = postgres_node_select(
        "WHERE user_id = $1 AND hostname = $2 AND deleted_at IS NULL ORDER BY id LIMIT 1",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(user_id)
        .bind(hostname)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

pub async fn update_from_auth_path(
    pool: &SqlitePool,
    id: i64,
    params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    let given_name = auth_path_given_name(pool, id, &params).await?;

    let tags = normalize_tags(params.tags);
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&expand_exit_routes(params.approved_routes))?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            machine_key = NULLIF(?, ''),
            node_key = NULLIF(?, ''),
            disco_key = NULLIF(?, ''),
            endpoints = ?,
            host_info = ?,
            ipv4 = ?,
            ipv6 = ?,
            hostname = NULLIF(?, ''),
            given_name = NULLIF(?, ''),
            user_id = ?,
            register_method = NULLIF(?, ''),
            tags = ?,
            auth_key_id = ?,
            expiry = CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            last_seen = CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            approved_routes = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(&host_info)
    .bind(&params.ipv4)
    .bind(&params.ipv6)
    .bind(&params.hostname)
    .bind(&given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(params.expiry)
    .bind(params.expiry)
    .bind(params.last_seen)
    .bind(params.last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn update_postgres_from_auth_path(
    pool: &PgPool,
    id: i64,
    params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    update_postgres_from_auth_path_on_connection(&mut conn, id, params).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn update_postgres_from_auth_path_on_connection(
    conn: &mut PgConnection,
    id: i64,
    params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    let given_name = auth_path_postgres_given_name(conn, id, &params).await?;

    let tags = normalize_tags(params.tags);
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&expand_exit_routes(params.approved_routes))?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            machine_key = NULLIF($1, ''),
            node_key = NULLIF($2, ''),
            disco_key = NULLIF($3, ''),
            endpoints = $4,
            host_info = $5,
            ipv4 = $6,
            ipv6 = $7,
            hostname = NULLIF($8, ''),
            given_name = NULLIF($9, ''),
            user_id = $10,
            register_method = NULLIF($11, ''),
            tags = $12,
            auth_key_id = $13,
            expiry = CASE
                WHEN $14::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($14::BIGINT)::DOUBLE PRECISION)
            END,
            last_seen = CASE
                WHEN $15::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($15::BIGINT)::DOUBLE PRECISION)
            END,
            approved_routes = $16,
            updated_at = to_timestamp(($17::BIGINT)::DOUBLE PRECISION)
        WHERE id = $18 AND deleted_at IS NULL
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(&host_info)
    .bind(&params.ipv4)
    .bind(&params.ipv6)
    .bind(&params.hostname)
    .bind(&given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(params.expiry)
    .bind(params.last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select("WHERE deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn list_by_ids(pool: &SqlitePool, ids: &[i64]) -> Result<Vec<HeadscaleNodeRow>> {
    if ids.is_empty() {
        return list(pool).await;
    }

    let query = node_select(&format!(
        "WHERE deleted_at IS NULL AND id IN ({}) ORDER BY id",
        sqlite_placeholders(ids.len())
    ));
    let mut query = sqlx::query_as::<_, HeadscaleNodeRow>(&query);
    for id in ids {
        query = query.bind(*id);
    }
    query.fetch_all(pool).await.map_err(DbError::from)
}

pub async fn list_peers(
    pool: &SqlitePool,
    node_id: i64,
    peer_ids: &[i64],
) -> Result<Vec<HeadscaleNodeRow>> {
    let query = if peer_ids.is_empty() {
        node_select("WHERE id != ? AND deleted_at IS NULL ORDER BY id")
    } else {
        node_select(&format!(
            "WHERE id != ? AND deleted_at IS NULL AND id IN ({}) ORDER BY id",
            sqlite_placeholders(peer_ids.len())
        ))
    };
    let mut query = sqlx::query_as::<_, HeadscaleNodeRow>(&query).bind(node_id);
    for id in peer_ids {
        query = query.bind(*id);
    }
    query.fetch_all(pool).await.map_err(DbError::from)
}

pub async fn list_ephemeral(pool: &SqlitePool) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select(
        "WHERE deleted_at IS NULL
         AND auth_key_id IN (SELECT id FROM pre_auth_keys WHERE ephemeral = 1)
         ORDER BY id",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn list_by_user(pool: &SqlitePool, user_id: i64) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select("WHERE user_id = ? AND deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres(pool: &PgPool) -> Result<Vec<HeadscaleNodeRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_on_connection(&mut conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_on_connection(conn: &mut PgConnection) -> Result<Vec<HeadscaleNodeRow>> {
    let query = postgres_node_select("WHERE deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_ids(pool: &PgPool, ids: &[i64]) -> Result<Vec<HeadscaleNodeRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_by_ids_on_connection(&mut conn, ids).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_ids_on_connection(
    conn: &mut PgConnection,
    ids: &[i64],
) -> Result<Vec<HeadscaleNodeRow>> {
    if ids.is_empty() {
        return list_postgres_on_connection(conn).await;
    }

    let query = postgres_node_select("WHERE deleted_at IS NULL AND id = ANY($1) ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(ids.to_vec())
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_peers(
    pool: &PgPool,
    node_id: i64,
    peer_ids: &[i64],
) -> Result<Vec<HeadscaleNodeRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_peers_on_connection(&mut conn, node_id, peer_ids).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_peers_on_connection(
    conn: &mut PgConnection,
    node_id: i64,
    peer_ids: &[i64],
) -> Result<Vec<HeadscaleNodeRow>> {
    let query = if peer_ids.is_empty() {
        postgres_node_select("WHERE id != $1 AND deleted_at IS NULL ORDER BY id")
    } else {
        postgres_node_select("WHERE id != $1 AND deleted_at IS NULL AND id = ANY($2) ORDER BY id")
    };
    let query = sqlx::query_as::<_, HeadscaleNodeRow>(&query).bind(node_id);
    let query = if peer_ids.is_empty() {
        query
    } else {
        query.bind(peer_ids.to_vec())
    };
    query.fetch_all(&mut *conn).await.map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_ephemeral(pool: &PgPool) -> Result<Vec<HeadscaleNodeRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_ephemeral_on_connection(&mut conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_ephemeral_on_connection(
    conn: &mut PgConnection,
) -> Result<Vec<HeadscaleNodeRow>> {
    let query = postgres_node_select(
        "WHERE deleted_at IS NULL
         AND auth_key_id IN (SELECT id FROM pre_auth_keys WHERE ephemeral = TRUE)
         ORDER BY id",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_user(pool: &PgPool, user_id: i64) -> Result<Vec<HeadscaleNodeRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_by_user_on_connection(&mut conn, user_id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_user_on_connection(
    conn: &mut PgConnection,
    user_id: i64,
) -> Result<Vec<HeadscaleNodeRow>> {
    let query = postgres_node_select("WHERE user_id = $1 AND deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

pub async fn set_tags(pool: &SqlitePool, id: i64, tags: Vec<String>) -> Result<HeadscaleNodeRow> {
    let tags = normalize_tags(tags);
    if tags.is_empty() {
        return Err(DbError::Constraint(
            "cannot remove all tags from a node - tagged nodes must have at least one tag".into(),
        ));
    }
    let clear_user_id = true;
    let tags = json_array(&tags)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            user_id = CASE WHEN ? THEN NULL ELSE user_id END,
            tags = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(clear_user_id)
    .bind(tags)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_tags(
    pool: &PgPool,
    id: i64,
    tags: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_tags_on_connection(&mut conn, id, tags).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_tags_on_connection(
    conn: &mut PgConnection,
    id: i64,
    tags: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let tags = normalize_tags(tags);
    if tags.is_empty() {
        return Err(DbError::Constraint(
            "cannot remove all tags from a node - tagged nodes must have at least one tag".into(),
        ));
    }
    let clear_user_id = true;
    let tags = json_array(&tags)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            user_id = CASE WHEN $1 THEN NULL ELSE user_id END,
            tags = $2,
            updated_at = to_timestamp(($3::BIGINT)::DOUBLE PRECISION)
        WHERE id = $4 AND deleted_at IS NULL
        ",
    )
    .bind(clear_user_id)
    .bind(tags)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn rename(pool: &SqlitePool, id: i64, new_given_name: &str) -> Result<HeadscaleNodeRow> {
    validate_given_name(new_given_name)?;
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM nodes
        WHERE given_name = ? AND id != ? AND deleted_at IS NULL
        ",
    )
    .bind(new_given_name)
    .bind(id)
    .fetch_one(pool)
    .await?;
    if count > 0 {
        return Err(DbError::General(NodeError::NameNotUnique.to_string()));
    }

    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET given_name = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(new_given_name)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn rename_postgres(
    pool: &PgPool,
    id: i64,
    new_given_name: &str,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    rename_postgres_on_connection(&mut conn, id, new_given_name).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn rename_postgres_on_connection(
    conn: &mut PgConnection,
    id: i64,
    new_given_name: &str,
) -> Result<HeadscaleNodeRow> {
    validate_given_name(new_given_name)?;
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM nodes
        WHERE given_name = $1 AND id != $2 AND deleted_at IS NULL
        ",
    )
    .bind(new_given_name)
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if count > 0 {
        return Err(DbError::General(NodeError::NameNotUnique.to_string()));
    }

    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET given_name = $1, updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(new_given_name)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn set_approved_routes(
    pool: &SqlitePool,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let routes = json_array(&expand_exit_routes(routes))?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET approved_routes = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(routes)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_approved_routes(
    pool: &PgPool,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_approved_routes_on_connection(&mut conn, id, routes).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_approved_routes_on_connection(
    conn: &mut PgConnection,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let routes = json_array(&expand_exit_routes(routes))?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET approved_routes = $1, updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(routes)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn set_host_info_routable_ips(
    pool: &SqlitePool,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let row = get_by_id(pool, id).await?;
    let mut host_info = row.host_info_value();
    if !host_info.is_object() {
        host_info = json!({});
    }
    if let Value::Object(fields) = &mut host_info {
        if routes.is_empty() {
            fields.remove("RoutableIPs");
        } else {
            fields.insert(
                "RoutableIPs".into(),
                Value::Array(routes.into_iter().map(Value::String).collect()),
            );
        }
    }

    let host_info = json_object_or_value(&host_info)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET host_info = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(host_info)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_host_info_routable_ips(
    pool: &PgPool,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_host_info_routable_ips_on_connection(&mut conn, id, routes).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_host_info_routable_ips_on_connection(
    conn: &mut PgConnection,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let row = get_postgres_by_id_on_connection(conn, id).await?;
    let mut host_info = row.host_info_value();
    if !host_info.is_object() {
        host_info = json!({});
    }
    if let Value::Object(fields) = &mut host_info {
        if routes.is_empty() {
            fields.remove("RoutableIPs");
        } else {
            fields.insert(
                "RoutableIPs".into(),
                Value::Array(routes.into_iter().map(Value::String).collect()),
            );
        }
    }

    let host_info = json_object_or_value(&host_info)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET host_info = $1, updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(host_info)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn set_expiry(
    pool: &SqlitePool,
    id: i64,
    expiry: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(expiry)
    .bind(expiry)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_expiry(
    pool: &PgPool,
    id: i64,
    expiry: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_expiry_on_connection(&mut conn, id, expiry).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_expiry_on_connection(
    conn: &mut PgConnection,
    id: i64,
    expiry: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = CASE
                WHEN $1::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($1::BIGINT)::DOUBLE PRECISION)
            END,
            updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(expiry)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn set_last_seen(
    pool: &SqlitePool,
    id: i64,
    last_seen: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            last_seen = CASE WHEN ? IS NULL THEN NULL ELSE datetime(?, 'unixepoch') END,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(last_seen)
    .bind(last_seen)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_last_seen(
    pool: &PgPool,
    id: i64,
    last_seen: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_last_seen_on_connection(&mut conn, id, last_seen).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_last_seen_on_connection(
    conn: &mut PgConnection,
    id: i64,
    last_seen: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            last_seen = CASE
                WHEN $1::BIGINT IS NULL THEN NULL
                ELSE to_timestamp(($1::BIGINT)::DOUBLE PRECISION)
            END,
            updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(last_seen)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn set_ip_addresses(
    pool: &SqlitePool,
    id: i64,
    ipv4: Option<String>,
    ipv6: Option<String>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            ipv4 = ?,
            ipv6 = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(ipv4)
    .bind(ipv6)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_ip_addresses(
    pool: &PgPool,
    id: i64,
    ipv4: Option<String>,
    ipv6: Option<String>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_ip_addresses_on_connection(&mut conn, id, ipv4, ipv6).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_ip_addresses_on_connection(
    conn: &mut PgConnection,
    id: i64,
    ipv4: Option<String>,
    ipv6: Option<String>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            ipv4 = $1,
            ipv6 = $2,
            updated_at = to_timestamp(($3::BIGINT)::DOUBLE PRECISION)
        WHERE id = $4 AND deleted_at IS NULL
        ",
    )
    .bind(ipv4)
    .bind(ipv6)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn logout(pool: &SqlitePool, id: i64) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = datetime(?, 'unixepoch'),
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn logout_postgres(pool: &PgPool, id: i64) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    logout_postgres_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn logout_postgres_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = to_timestamp(($1::BIGINT)::DOUBLE PRECISION),
            updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let affected = sqlx::query("DELETE FROM nodes WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let mut conn = pool.acquire().await?;
    destroy_postgres_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let affected = sqlx::query("DELETE FROM nodes WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    Ok(())
}

fn map_not_found(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound("node".into()),
        e => DbError::from(e),
    }
}

fn map_sqlx_err(e: sqlx::Error) -> DbError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DbError::General(NodeError::Exists.to_string())
        }
        _ => DbError::from(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Database,
        preauth_keys::{self, CreateParams as PreauthCreateParams},
        users::{self, CreateParams as UserCreateParams},
    };
    use sqlx::Row;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    async fn alice_id(db: &Database) -> i64 {
        users::create(
            db.pool(),
            UserCreateParams {
                name: "alice".into(),
                display_name: "Alice".into(),
                email: "alice@example.com".into(),
                provider_identifier: None,
                provider: REGISTER_METHOD_CLI.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap()
        .id
    }

    async fn auth_key_id(db: &Database, user_id: i64) -> i64 {
        auth_key_id_with_ephemeral(db, user_id, false).await
    }

    async fn auth_key_id_with_ephemeral(db: &Database, user_id: i64, ephemeral: bool) -> i64 {
        preauth_keys::create_for_test(
            db.pool(),
            PreauthCreateParams {
                user_id: user_id.to_string(),
                reusable: false,
                ephemeral,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap()
        .row
        .id
    }

    fn node_params(user_id: i64, auth_key_id: i64) -> CreateParams {
        CreateParams {
            machine_key: "mkey:abc".into(),
            node_key: "nodekey:abc".into(),
            disco_key: "discokey:abc".into(),
            endpoints: vec!["192.0.2.10:41641".into(), "[2001:db8::1]:41641".into()],
            host_info: json!({
                "Hostname": "alice-laptop",
                "OS": "linux",
            }),
            ipv4: Some("100.64.0.1".into()),
            ipv6: Some("fd7a:115c:a1e0::1".into()),
            hostname: "alice-laptop".into(),
            given_name: "alice-laptop".into(),
            user_id: Some(user_id),
            register_method: REGISTER_METHOD_AUTH_KEY.into(),
            tags: Vec::new(),
            auth_key_id: Some(auth_key_id),
            expiry: Some(4_102_444_800),
            last_seen: Some(1_700_000_000),
            approved_routes: vec!["10.0.0.0/24".into()],
        }
    }

    #[tokio::test]
    async fn create_matches_headscale_go_row_shape() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        assert_eq!(node.id, 1);
        assert_eq!(node.machine_key, "mkey:abc");
        assert_eq!(node.node_key, "nodekey:abc");
        assert_eq!(node.disco_key, "discokey:abc");
        assert_eq!(node.hostname, "alice-laptop");
        assert_eq!(node.given_name, "alice-laptop");
        assert_eq!(node.user_id, Some(user_id));
        assert_eq!(node.auth_key_id, Some(auth_key_id));
        assert_eq!(node.register_method, REGISTER_METHOD_AUTH_KEY);
        assert_eq!(
            node.endpoint_list(),
            vec!["192.0.2.10:41641", "[2001:db8::1]:41641"]
        );
        assert!(node.tag_list().is_empty());
        assert_eq!(node.approved_route_list(), vec!["10.0.0.0/24"]);
        assert_eq!(node.host_info_value()["Hostname"], "alice-laptop");
        assert_eq!(node.expiry, Some(4_102_444_800));
        assert_eq!(node.last_seen, Some(1_700_000_000));
        assert_eq!(node.created_at, node.updated_at);
        assert!(node.deleted_at.is_none());

        let raw = sqlx::query(
            "
            SELECT
                id,
                machine_key,
                node_key,
                given_name,
                typeof(user_id) AS user_id_type,
                user_id,
                typeof(auth_key_id) AS auth_key_id_type,
                auth_key_id,
                unixepoch(created_at) AS created_at,
                unixepoch(updated_at) AS updated_at,
                unixepoch(expiry) AS expiry,
                unixepoch(last_seen) AS last_seen,
                deleted_at
            FROM nodes
            WHERE id = ?
            ",
        )
        .bind(node.id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(raw.get::<i64, _>("id"), node.id);
        assert_eq!(raw.get::<String, _>("machine_key"), "mkey:abc");
        assert_eq!(raw.get::<String, _>("node_key"), "nodekey:abc");
        assert_eq!(raw.get::<String, _>("given_name"), "alice-laptop");
        assert_eq!(raw.get::<String, _>("user_id_type"), "integer");
        assert_eq!(raw.get::<i64, _>("user_id"), user_id);
        assert_eq!(raw.get::<String, _>("auth_key_id_type"), "integer");
        assert_eq!(raw.get::<i64, _>("auth_key_id"), auth_key_id);
        assert_eq!(raw.get::<i64, _>("created_at"), node.created_at);
        assert_eq!(raw.get::<i64, _>("updated_at"), node.updated_at);
        assert_eq!(raw.get::<i64, _>("expiry"), 4_102_444_800);
        assert_eq!(raw.get::<i64, _>("last_seen"), 1_700_000_000);
        assert!(raw.get::<Option<String>, _>("deleted_at").is_none());
    }

    #[tokio::test]
    async fn create_auto_derives_given_name_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;

        let mut first_params = node_params(user_id, auth_key_id);
        first_params.hostname = "Peer.One!".into();
        first_params.given_name.clear();
        let first = create(db.pool(), first_params).await.unwrap();
        assert_eq!(first.hostname, "Peer.One!");
        assert_eq!(first.given_name, "peer-one");

        let mut compound_suffix_params = node_params(user_id, auth_key_id);
        compound_suffix_params.machine_key = "mkey:compound-suffix".into();
        compound_suffix_params.node_key = "nodekey:compound-suffix".into();
        compound_suffix_params.disco_key = "discokey:compound-suffix".into();
        compound_suffix_params.ipv4 = Some("100.64.0.22".into());
        compound_suffix_params.ipv6 = Some("fd7a:115c:a1e0::22".into());
        compound_suffix_params.hostname = "Peer.localdomain.local".into();
        compound_suffix_params.given_name.clear();
        let compound_suffix = create(db.pool(), compound_suffix_params).await.unwrap();
        assert_eq!(compound_suffix.given_name, "peer");

        let mut duplicate_params = node_params(user_id, auth_key_id);
        duplicate_params.machine_key = "mkey:duplicate-host".into();
        duplicate_params.node_key = "nodekey:duplicate-host".into();
        duplicate_params.disco_key = "discokey:duplicate-host".into();
        duplicate_params.ipv4 = Some("100.64.0.2".into());
        duplicate_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        duplicate_params.hostname = "Peer.One!".into();
        duplicate_params.given_name.clear();
        let duplicate = create(db.pool(), duplicate_params).await.unwrap();
        assert_eq!(duplicate.given_name, "peer-one-1");

        let mut empty_params = node_params(user_id, auth_key_id);
        empty_params.machine_key = "mkey:empty-host".into();
        empty_params.node_key = "nodekey:empty-host".into();
        empty_params.disco_key = "discokey:empty-host".into();
        empty_params.ipv4 = Some("100.64.0.3".into());
        empty_params.ipv6 = Some("fd7a:115c:a1e0::3".into());
        empty_params.hostname = "!!!".into();
        empty_params.given_name.clear();
        let empty = create(db.pool(), empty_params).await.unwrap();
        assert_eq!(empty.given_name, "node");
    }

    #[tokio::test]
    async fn create_truncates_auto_given_name_before_collision_suffix() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let long_hostname = "node".repeat(20);
        let expected_base = "node".repeat(15) + "nod";

        let mut first_params = node_params(user_id, auth_key_id);
        first_params.hostname.clone_from(&long_hostname);
        first_params.given_name.clear();
        let first = create(db.pool(), first_params).await.unwrap();
        assert_eq!(first.given_name, expected_base);
        assert_eq!(first.given_name.len(), 63);

        let mut duplicate_params = node_params(user_id, auth_key_id);
        duplicate_params.machine_key = "mkey:long-duplicate".into();
        duplicate_params.node_key = "nodekey:long-duplicate".into();
        duplicate_params.disco_key = "discokey:long-duplicate".into();
        duplicate_params.ipv4 = Some("100.64.0.2".into());
        duplicate_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        duplicate_params.hostname = long_hostname;
        duplicate_params.given_name.clear();
        let duplicate = create(db.pool(), duplicate_params).await.unwrap();
        assert_eq!(duplicate.given_name, format!("{expected_base}-1"));
    }

    #[tokio::test]
    async fn list_helpers_match_headscale_go_id_and_peer_filters() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key = "mkey:second".into();
        second_params.node_key = "nodekey:second".into();
        second_params.disco_key = "discokey:second".into();
        second_params.hostname = "alice-phone".into();
        second_params.given_name = "alice-phone".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let all = list_by_ids(db.pool(), &[]).await.unwrap();
        assert_eq!(
            all.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![first.id, second.id]
        );

        assert!(list_by_ids(db.pool(), &[999]).await.unwrap().is_empty());
        let partial = list_by_ids(db.pool(), &[second.id, 999]).await.unwrap();
        assert_eq!(
            partial.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![second.id]
        );

        let peers = list_peers(db.pool(), first.id, &[]).await.unwrap();
        assert_eq!(
            peers.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![second.id]
        );
        let filtered_peers = list_peers(db.pool(), first.id, &[first.id, second.id, 999])
            .await
            .unwrap();
        assert_eq!(
            filtered_peers
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            vec![second.id]
        );

        assert_eq!(
            get_by_user_hostname(db.pool(), user_id, "alice-phone")
                .await
                .unwrap()
                .id,
            second.id
        );
        assert!(matches!(
            get_by_user_hostname(db.pool(), user_id, "missing").await,
            Err(DbError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn list_ephemeral_uses_assigned_preauth_key_flag() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let ephemeral_key_id = auth_key_id_with_ephemeral(&db, user_id, true).await;
        let mut ephemeral_params = node_params(user_id, ephemeral_key_id);
        ephemeral_params.machine_key = "mkey:ephemeral".into();
        ephemeral_params.node_key = "nodekey:ephemeral".into();
        ephemeral_params.disco_key = "discokey:ephemeral".into();
        ephemeral_params.hostname = "ephemeral".into();
        ephemeral_params.given_name = "ephemeral".into();
        ephemeral_params.ipv4 = Some("100.64.0.2".into());
        ephemeral_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let ephemeral = create(db.pool(), ephemeral_params).await.unwrap();

        let ephemeral_nodes = list_ephemeral(db.pool()).await.unwrap();
        assert_eq!(
            ephemeral_nodes
                .iter()
                .map(|node| (node.id, node.auth_key_id))
                .collect::<Vec<_>>(),
            vec![(ephemeral.id, Some(ephemeral_key_id))]
        );
    }

    #[tokio::test]
    async fn tagged_nodes_are_tag_owned_without_user_id() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let mut params = node_params(user_id, auth_key_id);
        params.tags = vec!["tag:dev".into()];

        let node = create(db.pool(), params).await.unwrap();

        assert_eq!(node.user_id, None);
        assert_eq!(node.tag_list(), vec!["tag:dev"]);
        assert!(list_by_user(db.pool(), user_id).await.unwrap().is_empty());
        let raw_user_id: Option<i64> = sqlx::query_scalar("SELECT user_id FROM nodes WHERE id = ?")
            .bind(node.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(raw_user_id, None);
    }

    #[tokio::test]
    async fn update_from_auth_path_rekeys_existing_node() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let original = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();
        let mut params = node_params(user_id, auth_key_id);
        params.node_key = "nodekey:def".into();
        params.disco_key = "discokey:def".into();
        params.endpoints = vec!["198.51.100.10:41641".into()];
        params.hostname = "alice-reauth".into();
        params.given_name = "alice-reauth".into();
        params.register_method = REGISTER_METHOD_OIDC.into();
        params.tags = Vec::new();
        params.auth_key_id = None;
        params.expiry = Some(4_102_444_800);
        params.last_seen = Some(1_800_000_000);
        params.approved_routes = vec!["::/0".into()];

        let updated = update_from_auth_path(db.pool(), original.id, params)
            .await
            .unwrap();

        assert_eq!(updated.id, original.id);
        assert_eq!(updated.machine_key, "mkey:abc");
        assert_eq!(updated.node_key, "nodekey:def");
        assert_eq!(updated.disco_key, "discokey:def");
        assert_eq!(updated.endpoint_list(), vec!["198.51.100.10:41641"]);
        assert_eq!(updated.given_name, "alice-reauth");
        assert_eq!(updated.user_id, Some(user_id));
        assert_eq!(updated.auth_key_id, None);
        assert_eq!(updated.register_method, REGISTER_METHOD_OIDC);
        assert!(updated.tag_list().is_empty());
        assert_eq!(updated.approved_route_list(), vec!["::/0", "0.0.0.0/0"]);
        assert_eq!(updated.created_at, original.created_at);
        assert!(updated.updated_at >= original.updated_at);
        assert_eq!(
            get_by_machine_key_and_user(db.pool(), "mkey:abc", user_id)
                .await
                .unwrap()
                .node_key,
            "nodekey:def"
        );
    }

    #[tokio::test]
    async fn update_from_auth_path_clears_user_id_for_tagged_node() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let original = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();
        let mut params = node_params(user_id, auth_key_id);
        params.node_key = "nodekey:tagged".into();
        params.given_name = "alice-tagged".into();
        params.tags = vec!["tag:server".into()];

        let updated = update_from_auth_path(db.pool(), original.id, params)
            .await
            .unwrap();

        assert_eq!(updated.id, original.id);
        assert_eq!(updated.user_id, None);
        assert_eq!(updated.tag_list(), vec!["tag:server"]);
        assert!(list_by_user(db.pool(), user_id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_from_auth_path_restores_user_id_when_tags_are_empty() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let mut original_params = node_params(user_id, auth_key_id);
        original_params.tags = vec!["tag:server".into()];
        let original = create(db.pool(), original_params).await.unwrap();
        assert_eq!(original.user_id, None);

        let mut params = node_params(user_id, auth_key_id);
        params.node_key = "nodekey:user-owned".into();
        params.tags = Vec::new();

        let updated = update_from_auth_path(db.pool(), original.id, params)
            .await
            .unwrap();

        assert_eq!(updated.user_id, Some(user_id));
        assert!(updated.tag_list().is_empty());
        assert_eq!(list_by_user(db.pool(), user_id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn update_from_auth_path_auto_bumps_colliding_given_name() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key = "mkey:def".into();
        second_params.node_key = "nodekey:def".into();
        second_params.disco_key = "discokey:def".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let mut reauth_params = node_params(user_id, auth_key_id);
        reauth_params.machine_key = "mkey:def".into();
        reauth_params.node_key = "nodekey:reauth".into();
        reauth_params.disco_key = "discokey:reauth".into();
        reauth_params.hostname = "alice-laptop".into();
        reauth_params.given_name.clear();
        reauth_params.ipv4 = Some("100.64.0.2".into());
        reauth_params.ipv6 = Some("fd7a:115c:a1e0::2".into());

        let updated = update_from_auth_path(db.pool(), second.id, reauth_params)
            .await
            .unwrap();
        assert_eq!(updated.given_name, "alice-laptop-1");
    }

    #[tokio::test]
    async fn update_from_auth_path_preserves_explicit_given_name_verbatim() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();
        let renamed = rename(db.pool(), node.id, "AdminName").await.unwrap();
        assert_eq!(renamed.given_name, "AdminName");

        let mut reauth_params = node_params(user_id, auth_key_id);
        reauth_params.node_key = "nodekey:reauth".into();
        reauth_params.hostname = "client-new-host".into();
        reauth_params.given_name = "AdminName".into();

        let updated = update_from_auth_path(db.pool(), node.id, reauth_params)
            .await
            .unwrap();
        assert_eq!(updated.hostname, "client-new-host");
        assert_eq!(updated.given_name, "AdminName");
    }

    #[tokio::test]
    async fn list_get_update_and_destroy_round_trip() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        assert_eq!(get_by_id(db.pool(), node.id).await.unwrap().id, node.id);
        assert_eq!(
            get_by_node_key(db.pool(), "nodekey:abc").await.unwrap().id,
            node.id
        );
        assert_eq!(
            get_by_machine_key(db.pool(), "mkey:abc").await.unwrap().id,
            node.id
        );
        assert_eq!(list(db.pool()).await.unwrap().len(), 1);
        assert_eq!(list_by_user(db.pool(), user_id).await.unwrap().len(), 1);

        let renamed = rename(db.pool(), node.id, "alice-renamed").await.unwrap();
        assert_eq!(renamed.given_name, "alice-renamed");

        let tagged = set_tags(
            db.pool(),
            node.id,
            vec!["tag:prod".into(), "tag:dev".into(), "tag:prod".into()],
        )
        .await
        .unwrap();
        assert_eq!(tagged.tag_list(), vec!["tag:dev", "tag:prod"]);
        assert_eq!(tagged.user_id, None);
        assert!(list_by_user(db.pool(), user_id).await.unwrap().is_empty());

        let empty_tags = set_tags(db.pool(), node.id, Vec::new())
            .await
            .expect_err("upstream rejects removing every forced tag");
        assert!(matches!(empty_tags, DbError::Constraint(_)));
        let still_tagged = get_by_id(db.pool(), node.id).await.unwrap();
        assert_eq!(still_tagged.tag_list(), vec!["tag:dev", "tag:prod"]);
        assert_eq!(still_tagged.user_id, None);

        let expired = set_expiry(db.pool(), node.id, Some(1_700_000_001))
            .await
            .unwrap();
        assert_eq!(expired.expiry, Some(1_700_000_001));

        let seen = set_last_seen(db.pool(), node.id, Some(1_700_000_002))
            .await
            .unwrap();
        assert_eq!(seen.last_seen, Some(1_700_000_002));

        let logged_out = logout(db.pool(), node.id).await.unwrap();
        assert_eq!(logged_out.machine_key, node.machine_key);
        assert_eq!(logged_out.disco_key, node.disco_key);
        assert_eq!(logged_out.endpoint_list(), node.endpoint_list());
        assert!(logged_out.expiry.is_some());

        destroy(db.pool(), node.id).await.unwrap();
        assert!(list(db.pool()).await.unwrap().is_empty());
        assert!(get_by_id(db.pool(), node.id).await.is_err());
    }

    #[tokio::test]
    async fn set_approved_routes_expands_exit_routes() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let routes = set_approved_routes(db.pool(), node.id, vec!["0.0.0.0/0".into()])
            .await
            .unwrap()
            .approved_route_list();
        assert_eq!(routes, vec!["0.0.0.0/0", "::/0"]);

        let routes = set_approved_routes(db.pool(), node.id, vec!["::/0".into()])
            .await
            .unwrap()
            .approved_route_list();
        assert_eq!(routes, vec!["::/0", "0.0.0.0/0"]);
    }

    #[tokio::test]
    async fn set_host_info_routable_ips_updates_available_routes_without_clearing_approved_routes()
    {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let mut params = node_params(user_id, auth_key_id);
        params.host_info = json!({
            "Hostname": "alice-laptop",
            "OS": "linux",
            "RoutableIPs": ["10.0.0.0/24", "10.1.0.0/24"],
        });
        params.approved_routes = vec!["10.0.0.0/24".into()];
        let node = create(db.pool(), params).await.unwrap();

        let updated = set_host_info_routable_ips(
            db.pool(),
            node.id,
            vec!["10.1.0.0/24".into(), "10.2.0.0/24".into()],
        )
        .await
        .unwrap();
        assert_eq!(
            updated.host_info_value()["RoutableIPs"],
            serde_json::json!(["10.1.0.0/24", "10.2.0.0/24"])
        );
        assert_eq!(updated.approved_route_list(), vec!["10.0.0.0/24"]);

        let cleared = set_host_info_routable_ips(db.pool(), node.id, Vec::new())
            .await
            .unwrap();
        assert!(cleared.host_info_value().get("RoutableIPs").is_none());
        assert_eq!(cleared.approved_route_list(), vec!["10.0.0.0/24"]);
    }

    #[tokio::test]
    async fn set_ip_addresses_updates_ipv4_and_ipv6_only() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let updated = set_ip_addresses(
            db.pool(),
            node.id,
            Some("100.64.0.44".into()),
            Some("fd7a:115c:a1e0::44".into()),
        )
        .await
        .unwrap();

        assert_eq!(updated.ipv4.as_deref(), Some("100.64.0.44"));
        assert_eq!(updated.ipv6.as_deref(), Some("fd7a:115c:a1e0::44"));
        assert_eq!(updated.node_key, node.node_key);
        assert_eq!(updated.approved_route_list(), node.approved_route_list());
    }

    #[tokio::test]
    async fn create_rejects_duplicate_manual_addresses() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut duplicate_ipv4 = node_params(user_id, auth_key_id);
        duplicate_ipv4.machine_key = "mkey:dup-ipv4".into();
        duplicate_ipv4.node_key = "nodekey:dup-ipv4".into();
        duplicate_ipv4.disco_key = "discokey:dup-ipv4".into();
        duplicate_ipv4.hostname = "dup-ipv4".into();
        duplicate_ipv4.given_name = "dup-ipv4".into();
        duplicate_ipv4.ipv6 = Some("fd7a:115c:a1e0::44".into());
        let err = create(db.pool(), duplicate_ipv4).await.unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        let mut duplicate_ipv6 = node_params(user_id, auth_key_id);
        duplicate_ipv6.machine_key = "mkey:dup-ipv6".into();
        duplicate_ipv6.node_key = "nodekey:dup-ipv6".into();
        duplicate_ipv6.disco_key = "discokey:dup-ipv6".into();
        duplicate_ipv6.hostname = "dup-ipv6".into();
        duplicate_ipv6.given_name = "dup-ipv6".into();
        duplicate_ipv6.ipv4 = Some("100.64.0.44".into());
        let err = create(db.pool(), duplicate_ipv6).await.unwrap_err();
        assert!(matches!(err, DbError::General(_)));
    }

    #[tokio::test]
    async fn create_rejects_duplicate_live_node_key() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut duplicate = node_params(user_id, auth_key_id);
        duplicate.machine_key = "mkey:duplicate-node-key".into();
        duplicate.disco_key = "discokey:duplicate-node-key".into();
        duplicate.hostname = "duplicate-node-key".into();
        duplicate.given_name = "duplicate-node-key".into();
        duplicate.ipv4 = Some("100.64.0.44".into());
        duplicate.ipv6 = Some("fd7a:115c:a1e0::44".into());
        let err = create(db.pool(), duplicate).await.unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        let mut empty_key = node_params(user_id, auth_key_id);
        empty_key.machine_key = "mkey:empty-node-key".into();
        empty_key.node_key.clear();
        empty_key.disco_key = "discokey:empty-node-key".into();
        empty_key.hostname = "empty-node-key".into();
        empty_key.given_name = "empty-node-key".into();
        empty_key.ipv4 = Some("100.64.0.45".into());
        empty_key.ipv6 = Some("fd7a:115c:a1e0::45".into());
        create(db.pool(), empty_key).await.unwrap();

        let mut second_empty_key = node_params(user_id, auth_key_id);
        second_empty_key.machine_key = "mkey:second-empty-node-key".into();
        second_empty_key.node_key.clear();
        second_empty_key.disco_key = "discokey:second-empty-node-key".into();
        second_empty_key.hostname = "second-empty-node-key".into();
        second_empty_key.given_name = "second-empty-node-key".into();
        second_empty_key.ipv4 = Some("100.64.0.46".into());
        second_empty_key.ipv6 = Some("fd7a:115c:a1e0::46".into());
        create(db.pool(), second_empty_key).await.unwrap();
    }

    #[tokio::test]
    async fn update_from_auth_path_rejects_duplicate_live_node_key() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key = "mkey:def".into();
        second_params.node_key = "nodekey:def".into();
        second_params.disco_key = "discokey:def".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let mut duplicate = node_params(user_id, auth_key_id);
        duplicate.machine_key = "mkey:def".into();
        duplicate.node_key = first.node_key;
        duplicate.disco_key = "discokey:duplicate-node-key-update".into();
        duplicate.hostname = "duplicate-node-key-update".into();
        duplicate.given_name = "duplicate-node-key-update".into();
        duplicate.ipv4 = Some("100.64.0.47".into());
        duplicate.ipv6 = Some("fd7a:115c:a1e0::47".into());
        let err = update_from_auth_path(db.pool(), second.id, duplicate)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        assert_eq!(
            get_by_id(db.pool(), second.id).await.unwrap().node_key,
            "nodekey:def"
        );
    }

    #[tokio::test]
    async fn set_ip_addresses_rejects_duplicate_manual_addresses() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key = "mkey:def".into();
        second_params.node_key = "nodekey:def".into();
        second_params.disco_key = "discokey:def".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let err = set_ip_addresses(
            db.pool(),
            second.id,
            first.ipv4.clone(),
            Some("fd7a:115c:a1e0::3".into()),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        let err = set_ip_addresses(
            db.pool(),
            second.id,
            Some("100.64.0.3".into()),
            first.ipv6.clone(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DbError::General(_)));
    }

    #[tokio::test]
    async fn rename_validates_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        assert_eq!(
            rename(db.pool(), node.id, "Alice")
                .await
                .unwrap()
                .given_name,
            "Alice"
        );
        assert_eq!(
            rename(db.pool(), node.id, "a").await.unwrap().given_name,
            "a"
        );
        assert!(rename(db.pool(), node.id, "alice_laptop").await.is_err());
        assert!(rename(db.pool(), node.id, "-alice").await.is_err());
        assert!(rename(db.pool(), node.id, "alice-").await.is_err());
        assert!(rename(db.pool(), node.id, "alice.laptop").await.is_err());
    }

    #[tokio::test]
    async fn rename_rejects_duplicate_given_name() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key = "mkey:def".into();
        second_params.node_key = "nodekey:def".into();
        second_params.disco_key = "discokey:def".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let err = rename(db.pool(), second.id, &first.given_name)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::General(_)));
    }
}
