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

fn validate_given_name(name: &str) -> Result<()> {
    crate::users::validate_hostname(name).map_err(|e| DbError::General(e.to_string()))
}

pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<HeadscaleNodeRow> {
    if !params.given_name.is_empty() {
        validate_given_name(&params.given_name)?;
    }

    let now = now_unix();
    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&params.tags)?;
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
    .bind(&params.given_name)
    .bind(params.user_id)
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

pub async fn update_from_auth_path(
    pool: &SqlitePool,
    id: i64,
    params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    if !params.given_name.is_empty() {
        validate_given_name(&params.given_name)?;
    }

    let duplicate_given_name_count: i64 = sqlx::query_scalar(
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
    if duplicate_given_name_count > 0 {
        return Err(DbError::General(NodeError::NameNotUnique.to_string()));
    }

    let endpoints = json_array(&params.endpoints)?;
    let host_info = json_object_or_value(&params.host_info)?;
    let tags = json_array(&normalize_tags(params.tags))?;
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
    .bind(&params.given_name)
    .bind(params.user_id)
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

pub async fn list(pool: &SqlitePool) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select("WHERE deleted_at IS NULL ORDER BY id");
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

pub async fn set_tags(pool: &SqlitePool, id: i64, tags: Vec<String>) -> Result<HeadscaleNodeRow> {
    let tags = json_array(&normalize_tags(tags))?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET tags = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
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
        preauth_keys::create_for_test(
            db.pool(),
            PreauthCreateParams {
                user_id: user_id.to_string(),
                reusable: false,
                ephemeral: false,
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
            tags: vec!["tag:dev".into()],
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
        assert_eq!(node.tag_list(), vec!["tag:dev"]);
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
    async fn rename_validates_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        assert!(rename(db.pool(), node.id, "Alice").await.is_err());
        assert!(rename(db.pool(), node.id, "a").await.is_err());
        assert!(rename(db.pool(), node.id, "alice_laptop").await.is_err());
        assert!(rename(db.pool(), node.id, "-alice").await.is_err());
        assert!(rename(db.pool(), node.id, "alice-").await.is_err());
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
        let second = create(db.pool(), second_params).await.unwrap();

        let err = rename(db.pool(), second.id, &first.given_name)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::General(_)));
    }
}
