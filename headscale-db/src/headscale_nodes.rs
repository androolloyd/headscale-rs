//! Headscale-go-compatible node persistence.
//!
//! This module owns the canonical `nodes` table that mirrors
//! `juanfont/headscale@v0.29.5:hscontrol/types/node.go`. Octra's
//! mesh-oriented node store remains in [`crate::nodes`] and persists to
//! `octra_nodes`, so Octra-specific shape does not occupy the upstream
//! table name.

use crate::{DbError, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use headscale_api_acl::go_key::PublicKeyKind;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{Connection, PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};

pub const REGISTER_METHOD_AUTH_KEY: &str = "authkey";
pub const REGISTER_METHOD_CLI: &str = "cli";
pub const REGISTER_METHOD_OIDC: &str = "oidc";
const AUTO_GIVEN_NAME_RETRY_LIMIT: usize = 64;

mod cached_registration;
pub use cached_registration::{
    CachedNodeRegistration, RegistrationAuthKey, save_cached_registration,
    save_cached_registration_on_connection,
};
mod new_associations;
#[cfg(feature = "postgres-sqlx")]
pub(crate) use new_associations::save_postgres_user as save_postgres_captured_user;
pub(crate) use new_associations::save_sqlite_user as save_captured_user;

pub use new_associations::{
    NewNodeAssociations, NewNodeSave, create_new_registration_with_associations,
    create_new_registration_with_associations_on_connection, create_with_associations,
    create_with_associations_on_connection,
};
#[cfg(feature = "postgres-sqlx")]
pub use new_associations::{
    create_postgres_new_registration_with_associations,
    create_postgres_new_registration_with_associations_on_connection,
    create_postgres_with_associations, create_postgres_with_associations_on_connection,
};
mod new_registration;
#[cfg(feature = "postgres-sqlx")]
pub use cached_registration::{
    save_postgres_cached_registration, save_postgres_cached_registration_on_connection,
};
pub use new_registration::{
    NewNodeRegistration, create_new_registration, create_new_registration_on_connection,
};
#[cfg(feature = "postgres-sqlx")]
pub use new_registration::{
    create_postgres_new_registration, create_postgres_new_registration_on_connection,
};

/// The column mask used by Go State.persistNode. Expiry, AuthKeyID,
/// CreatedAt and DeletedAt deliberately have no fields in this type.
#[derive(Clone, Debug)]
pub struct CachedNodeSnapshot {
    pub id: i64,
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
    pub last_seen: Option<DateTime<Utc>>,
    pub approved_routes: Option<Vec<String>>,
}

struct EncodedCachedNode {
    node: CachedNodeSnapshot,
    endpoints: Option<String>,
    host_info: Option<String>,
    tags: Option<String>,
    approved_routes: Option<String>,
}

impl CachedNodeSnapshot {
    fn encode(mut self) -> Result<EncodedCachedNode> {
        if self.id <= 0 || self.user_id.is_some_and(|id| id < 0) {
            return Err(DbError::General("invalid cached node identity".into()));
        }
        self.machine_key =
            crate::stored_text::key_for_write(&self.machine_key, PublicKeyKind::Machine)?;
        self.node_key = crate::stored_text::key_for_write(&self.node_key, PublicKeyKind::Node)?;
        self.disco_key = crate::stored_text::key_for_write(&self.disco_key, PublicKeyKind::Disco)?;
        self.ipv4 = crate::stored_text::optional_address(self.ipv4.as_deref())?;
        self.ipv6 = crate::stored_text::optional_address(self.ipv6.as_deref())?;
        let endpoints = self
            .endpoints
            .as_ref()
            .map(|values| json_array(&crate::stored_json::endpoint_values(values)?))
            .transpose()?;
        let host_info = self
            .host_info
            .as_ref()
            .map(host_info_for_write)
            .transpose()?
            .flatten();
        let tags = self
            .tags
            .as_ref()
            .map(|values| json_array(values))
            .transpose()?;
        let approved_routes = self
            .approved_routes
            .as_ref()
            .map(|values| json_array(&crate::stored_json::prefix_values(values)?))
            .transpose()?;
        Ok(EncodedCachedNode {
            node: self,
            endpoints,
            host_info,
            tags,
            approved_routes,
        })
    }
}

/// Write the freshly re-read cache snapshot. Like GORM Updates, this does not
/// insert a missing row and a zero affected-row count is not a save error.
pub async fn save_cached_node_snapshot(
    pool: &SqlitePool,
    snapshot: CachedNodeSnapshot,
) -> Result<()> {
    let values = snapshot.encode()?;
    let node = &values.node;
    let last_seen = node
        .last_seen
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true));
    sqlx::query("UPDATE nodes SET machine_key = ?, node_key = ?, disco_key = ?, endpoints = ?, host_info = ?, ipv4 = ?, ipv6 = ?, hostname = ?, given_name = ?, user_id = ?, register_method = ?, tags = ?, last_seen = ?, approved_routes = ?, updated_at = ? WHERE id = ?")
        .bind(&node.machine_key).bind(&node.node_key).bind(&node.disco_key)
        .bind(values.endpoints.as_deref()).bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref()).bind(node.ipv6.as_deref())
        .bind(&node.hostname).bind(&node.given_name).bind(node.user_id)
        .bind(&node.register_method).bind(values.tags.as_deref())
        .bind(last_seen).bind(values.approved_routes.as_deref())
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true)).bind(node.id)
        .execute(pool).await.map_err(DbError::from)?;
    Ok(())
}

/// Go NodeSetExpiry updates only expiry and its automatic UpdatedAt clock.
/// Like Gorm Update, no affected row is not an error and no row is inserted.
pub async fn save_cached_node_expiry(
    pool: &SqlitePool,
    id: i64,
    expiry: Option<DateTime<Utc>>,
) -> Result<()> {
    let expiry = expiry.map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    sqlx::query("UPDATE nodes SET expiry = ?, updated_at = ? WHERE id = ?")
        .bind(expiry)
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true))
        .bind(id)
        .execute(pool)
        .await
        .map_err(DbError::from)?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn save_postgres_cached_node_expiry(
    pool: &PgPool,
    id: i64,
    expiry: Option<DateTime<Utc>>,
) -> Result<()> {
    let expiry = expiry.map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    sqlx::query(
        "UPDATE nodes SET expiry = $1::TIMESTAMPTZ, updated_at = $2::TIMESTAMPTZ WHERE id = $3",
    )
    .bind(expiry)
    .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true))
    .bind(id)
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn save_postgres_cached_node_snapshot(
    pool: &PgPool,
    snapshot: CachedNodeSnapshot,
) -> Result<()> {
    let values = snapshot.encode()?;
    let node = &values.node;
    let last_seen = node
        .last_seen
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Micros, true));
    sqlx::query("UPDATE nodes SET machine_key = $1, node_key = $2, disco_key = $3, endpoints = $4, host_info = $5, ipv4 = $6, ipv6 = $7, hostname = $8, given_name = $9, user_id = $10, register_method = $11, tags = $12, last_seen = $13::TIMESTAMPTZ, approved_routes = $14, updated_at = $15::TIMESTAMPTZ WHERE id = $16")
        .bind(&node.machine_key).bind(&node.node_key).bind(&node.disco_key)
        .bind(values.endpoints.as_deref()).bind(values.host_info.as_deref())
        .bind(node.ipv4.as_deref()).bind(node.ipv6.as_deref())
        .bind(&node.hostname).bind(&node.given_name).bind(node.user_id)
        .bind(&node.register_method).bind(values.tags.as_deref())
        .bind(last_seen).bind(values.approved_routes.as_deref())
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)).bind(node.id)
        .execute(pool).await.map_err(DbError::from)?;
    Ok(())
}

// Expiry is a Go *time.Time: preserve SQL NULL separately from an explicit
// zero time. Other instants on 0001-01-01 can already be expired.
// Keep the SQLite storage type through decoding; the row adapter validates
// and canonicalizes the instant before downstream node hydration reads it.
const NODE_COLUMNS: &str = r"
        id,
        machine_key,
        node_key,
        disco_key,
        endpoints,
        host_info,
        ipv4,
        ipv6,
        COALESCE(hostname, '') AS hostname,
        COALESCE(given_name, '') AS given_name,
        user_id,
        COALESCE(register_method, '') AS register_method,
        tags,
        auth_key_id,
        CASE
            WHEN expiry IS NULL THEN NULL
            WHEN typeof(expiry) = 'integer' THEN expiry
            ELSE unixepoch(expiry)
        END AS expiry,
        json_array(
            CASE WHEN typeof(expiry) = 'integer' AND EXISTS (
                SELECT 1 FROM main.sqlite_master
                WHERE type = 'table' AND name = '_sqlx_migrations'
            ) THEN 'legacy_integer' ELSE typeof(expiry) END,
            CASE WHEN typeof(expiry) = 'blob' THEN NULL ELSE CAST(expiry AS TEXT) END,
            (SELECT cid FROM pragma_table_info('nodes') WHERE name = 'expiry'),
            'expiry'
        ) AS expiry_text,
        CASE
            WHEN last_seen IS NULL THEN NULL
            WHEN typeof(last_seen) = 'integer' THEN last_seen
            ELSE unixepoch(last_seen)
        END AS last_seen,
        CAST(last_seen AS TEXT) AS last_seen_text,
        approved_routes,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
        COALESCE(CAST(created_at AS TEXT), '') AS created_at_text,
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

// Go Node.DeletedAt is *time.Time, not gorm.DeletedAt. Native node queries
// include timestamp-marked rows; only User/Policy have Gorm soft-delete scopes.
pub(crate) fn node_select(suffix: &str) -> String {
    format!("SELECT {NODE_COLUMNS} FROM nodes {suffix}")
}

fn key_identity_sql(column: &str, kind: PublicKeyKind) -> String {
    format!("LOWER(COALESCE({column}, '{}'))", kind.zero_text())
}

fn sqlite_placeholders(count: usize) -> String {
    (0..count).map(|_| "?").collect::<Vec<_>>().join(", ")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_NODE_COLUMNS: &str = r#"
        id,
        machine_key,
        node_key,
        disco_key,
        endpoints,
        host_info,
        ipv4,
        ipv6,
        COALESCE(hostname, '') AS hostname,
        COALESCE(given_name, '') AS given_name,
        user_id,
        COALESCE(register_method, '') AS register_method,
        tags,
        auth_key_id,
        FLOOR(EXTRACT(EPOCH FROM expiry))::BIGINT AS expiry,
        to_char(expiry AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expiry_text,
        FLOOR(EXTRACT(EPOCH FROM last_seen))::BIGINT AS last_seen,
        to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS last_seen_text,
        approved_routes,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        COALESCE(to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS created_at_text,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM updated_at))::BIGINT, 0) AS updated_at,
        FLOOR(EXTRACT(EPOCH FROM deleted_at))::BIGINT AS deleted_at
"#;

#[cfg(feature = "postgres-sqlx")]
pub(crate) fn postgres_node_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_NODE_COLUMNS} FROM nodes {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadscaleNodeRow {
    pub id: i64,
    #[sqlx(try_from = "crate::stored_text::MachineKeyColumn")]
    pub machine_key: String,
    #[sqlx(try_from = "crate::stored_text::NodeKeyColumn")]
    pub node_key: String,
    #[sqlx(try_from = "crate::stored_text::DiscoKeyColumn")]
    pub disco_key: String,
    #[sqlx(try_from = "crate::stored_json::EndpointListColumn")]
    pub endpoints: String,
    #[sqlx(try_from = "crate::stored_json::HostInfoColumn")]
    pub host_info: String,
    #[sqlx(try_from = "crate::stored_text::NullableAddrColumn")]
    pub ipv4: Option<String>,
    #[sqlx(try_from = "crate::stored_text::NullableAddrColumn")]
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    pub user_id: Option<i64>,
    pub register_method: String,
    #[sqlx(try_from = "crate::stored_json::StringListColumn")]
    pub tags: String,
    pub auth_key_id: Option<i64>,
    pub expiry: Option<i64>,
    #[sqlx(try_from = "crate::preauth_keys::timestamp::CanonicalExpirationColumn")]
    pub expiry_text: Option<String>,
    pub last_seen: Option<i64>,
    pub last_seen_text: Option<String>,
    #[sqlx(try_from = "crate::stored_json::PrefixListColumn")]
    pub approved_routes: String,
    pub created_at: i64,
    pub created_at_text: String,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

impl HeadscaleNodeRow {
    /// Fallible typed-key access for manually built/deserialized rows. SQL rows
    /// already pass the corresponding column decoder, including NULL zeroes.
    pub fn try_machine_key(&self) -> Result<String> {
        crate::stored_text::key_for_write(&self.machine_key, PublicKeyKind::Machine)
    }

    pub fn try_node_key(&self) -> Result<String> {
        crate::stored_text::key_for_write(&self.node_key, PublicKeyKind::Node)
    }

    pub fn try_disco_key(&self) -> Result<String> {
        crate::stored_text::key_for_write(&self.disco_key, PublicKeyKind::Disco)
    }

    /// Convenience for validated SQL rows; manually constructed rows needing
    /// a fallible decision should use try_endpoint_list.
    pub fn endpoint_list(&self) -> Vec<String> {
        self.try_endpoint_list().unwrap_or_default()
    }

    /// Decode netip endpoints, retaining Go's zero value for null/empty slots.
    pub fn try_endpoint_list(&self) -> Result<Vec<String>> {
        crate::stored_json::endpoint_list(&self.endpoints)
    }

    pub fn host_info_value(&self) -> Value {
        self.try_host_info_value().unwrap_or_else(|_| json!({}))
    }

    /// SQL rows have already passed typed Hostinfo decoding. Manual rows must
    /// not turn malformed policy/route inputs into an empty snapshot.
    pub fn try_host_info_value(&self) -> Result<Value> {
        crate::stored_hostinfo::from_bytes(self.host_info.as_bytes())
    }

    /// Convenience for validated SQL rows. Use try_tag_list for authorization
    /// decisions on manually constructed or deserialized row values.
    pub fn tag_list(&self) -> Vec<String> {
        self.try_tag_list().unwrap_or_default()
    }

    /// Decode tag ownership without interpreting malformed data as untagged.
    pub fn try_tag_list(&self) -> Result<Vec<String>> {
        crate::stored_json::string_list(&self.tags)
    }

    /// Convenience for validated SQL rows. Use try_approved_route_list when
    /// approval input did not pass the SQL row decoder.
    pub fn approved_route_list(&self) -> Vec<String> {
        self.try_approved_route_list().unwrap_or_default()
    }

    /// Decode prefixes without silently discarding malformed route approvals.
    pub fn try_approved_route_list(&self) -> Result<Vec<String>> {
        crate::stored_json::prefix_list(&self.approved_routes)
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
    pub expiry_precise: Option<DateTime<Utc>>,
    pub last_seen: Option<i64>,
    pub last_seen_precise: Option<DateTime<Utc>>,
    pub approved_routes: Vec<String>,
}

impl CreateParams {
    pub(crate) fn canonicalize_keys(&mut self) -> Result<()> {
        let machine_key =
            crate::stored_text::key_for_write(&self.machine_key, PublicKeyKind::Machine)?;
        let node_key = crate::stored_text::key_for_write(&self.node_key, PublicKeyKind::Node)?;
        let disco_key = crate::stored_text::key_for_write(&self.disco_key, PublicKeyKind::Disco)?;
        self.machine_key = machine_key;
        self.node_key = node_key;
        self.disco_key = disco_key;
        Ok(())
    }
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
            expiry_precise: None,
            last_seen: None,
            last_seen_precise: None,
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

fn last_seen_text(params: &CreateParams, format: SecondsFormat) -> Option<String> {
    params
        .last_seen_precise
        .or_else(|| {
            params
                .last_seen
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        })
        .map(|value| value.to_rfc3339_opts(format, true))
}

fn expiry_text(params: &CreateParams, format: SecondsFormat) -> Option<String> {
    params
        .expiry_precise
        .or_else(|| {
            params
                .expiry
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
        })
        .map(|value| value.to_rfc3339_opts(format, true))
}

fn json_array(values: &[String]) -> Result<String> {
    crate::stored_json::text_for_write(values)
}

fn host_info_for_write(value: &Value) -> Result<Option<String>> {
    crate::stored_hostinfo::text_for_write(value)
}

fn normalize_tags(mut tags: Vec<String>) -> Vec<String> {
    tags.sort();
    tags.dedup();
    tags
}

fn tag_owned_user_id(user_id: Option<i64>, tags: &[String]) -> Option<i64> {
    if tags.is_empty() { user_id } else { None }
}

fn normalize_approved_routes(routes: &[String]) -> Result<Vec<String>> {
    let routes = crate::stored_json::prefix_values(routes)?;
    let mut normalized = Vec::with_capacity(routes.len() + 2);
    for route in routes {
        if route == "0.0.0.0/0" || route == "::/0" {
            normalized.push("0.0.0.0/0".to_string());
            normalized.push("::/0".to_string());
        } else {
            normalized.push(route);
        }
    }

    normalized.sort_by(|a, b| {
        headscale_api_acl::go_netip::prefix_compare(a, b).unwrap_or_else(|| a.cmp(b))
    });
    normalized.dedup();
    Ok(normalized)
}

fn is_dns_label_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn validate_given_name(name: &str) -> Result<()> {
    headscale_api_acl::go_dnsname::valid_label(name).map_err(DbError::General)
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
    conn: &mut SqliteConnection,
    self_id: Option<i64>,
    hostname: &str,
) -> Result<String> {
    let base = auto_given_name_base(hostname);
    let rows: Vec<String> = sqlx::query_scalar(
        "
        SELECT given_name
        FROM nodes
        WHERE given_name IS NOT NULL
          AND given_name != ''
          AND (? IS NULL OR id != ?)
        ",
    )
    .bind(self_id)
    .bind(self_id)
    .fetch_all(&mut *conn)
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
        WHERE given_name IS NOT NULL
          AND given_name != ''
          AND ($1::BIGINT IS NULL OR id != $1)
        ",
    )
    .bind(self_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(resolve_given_name_from_existing(&base, rows))
}

async fn create_given_name(conn: &mut SqliteConnection, params: &CreateParams) -> Result<String> {
    if params.given_name.is_empty() {
        resolve_auto_given_name(conn, None, &params.hostname).await
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

async fn auth_path_given_name(
    conn: &mut SqliteConnection,
    id: i64,
    params: &CreateParams,
) -> Result<String> {
    if params.given_name.is_empty() {
        return resolve_auto_given_name(conn, Some(id), &params.hostname).await;
    }

    validate_given_name(&params.given_name)?;
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM nodes
        WHERE given_name = ? AND id != ?
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
        WHERE given_name = $1 AND id != $2
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
    let mut conn = pool.acquire().await?;
    create_on_connection(&mut conn, params).await
}

pub async fn create_on_connection(
    conn: &mut SqliteConnection,
    mut params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let retry_auto_given_name = params.given_name.is_empty();
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = create_given_name(conn, &params).await?;
        match create_with_given_name(conn, &params, &given_name).await {
            Ok(node) => return Ok(node),
            Err(e) if retry_auto_given_name && is_given_name_unique_violation(&e) => {}
            Err(e) => return Err(map_non_retry_write_err(e)),
        }
    }

    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

async fn create_with_given_name(
    conn: &mut SqliteConnection,
    params: &CreateParams,
    given_name: &str,
) -> Result<HeadscaleNodeRow> {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    let last_seen = last_seen_text(params, SecondsFormat::Nanos);
    let expiry = expiry_text(params, SecondsFormat::Nanos);
    let tags = normalize_tags(params.tags.clone());
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let ipv4 = crate::stored_text::optional_address(params.ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(params.ipv6.as_deref())?;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;

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
            ?,
            ?,
            ?,
            ?,
            ?,
            NULL
        )
        RETURNING id
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(host_info.as_deref())
    .bind(&ipv4)
    .bind(&ipv6)
    .bind(&params.hostname)
    .bind(given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(expiry)
    .bind(last_seen)
    .bind(&approved_routes)
    .bind(&now)
    .bind(&now)
    .fetch_one(&mut *conn)
    .await
    .map_err(DbError::from)?;

    let query = node_select("WHERE id = ?");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres(pool: &PgPool, params: CreateParams) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    create_postgres_on_connection(&mut conn, params).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_on_connection(
    conn: &mut PgConnection,
    mut params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let retry_auto_given_name = params.given_name.is_empty();
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = create_postgres_given_name(conn, &params).await?;
        // A failed INSERT/UPDATE aborts a PostgreSQL transaction. A savepoint
        // lets generated-name retries proceed inside the enclosing registration.
        let mut attempt = conn.begin().await?;
        let result = create_postgres_with_given_name(&mut attempt, &params, &given_name).await;
        match result {
            Ok(node) => {
                attempt.commit().await?;
                return Ok(node);
            }
            Err(error) => {
                attempt.rollback().await?;
                if !(retry_auto_given_name && is_given_name_unique_violation(&error)) {
                    return Err(map_non_retry_write_err(error));
                }
            }
        }
    }

    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

#[cfg(feature = "postgres-sqlx")]
async fn create_postgres_with_given_name(
    conn: &mut PgConnection,
    params: &CreateParams,
    given_name: &str,
) -> Result<HeadscaleNodeRow> {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let last_seen = last_seen_text(params, SecondsFormat::Micros);
    let expiry = expiry_text(params, SecondsFormat::Micros);
    let tags = normalize_tags(params.tags.clone());
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let ipv4 = crate::stored_text::optional_address(params.ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(params.ipv6.as_deref())?;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;

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
            $14::TIMESTAMPTZ,
            $15::TIMESTAMPTZ,
            $16,
            $17::TIMESTAMPTZ,
            $18::TIMESTAMPTZ,
            NULL
        )
        RETURNING id
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(host_info.as_deref())
    .bind(&ipv4)
    .bind(&ipv6)
    .bind(&params.hostname)
    .bind(given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(expiry)
    .bind(last_seen)
    .bind(&approved_routes)
    .bind(&now)
    .bind(&now)
    .fetch_one(&mut *conn)
    .await
    .map_err(DbError::from)?;

    let query = postgres_node_select("WHERE id = $1");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
}

/// Persist client map fields without rewriting ownership, expiry, auth-key
/// references, IP assignments, tags or registration identity.
pub async fn update_runtime_state(
    pool: &SqlitePool,
    expected: &HeadscaleNodeRow,
    mut params: CreateParams,
    allow_auto_rename: bool,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let expected_node_key =
        crate::stored_text::key_for_write(&expected.node_key, PublicKeyKind::Node)?;
    let expected_machine_key =
        crate::stored_text::key_for_write(&expected.machine_key, PublicKeyKind::Machine)?;
    let node_identity = key_identity_sql("node_key", PublicKeyKind::Node);
    let machine_identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    if params.node_key != expected_node_key || params.machine_key != expected_machine_key {
        return Err(DbError::Constraint(
            "map update cannot change node or machine key".into(),
        ));
    }
    let mut conn = pool.acquire().await?;
    let rename =
        !params.hostname.is_empty() && params.hostname != expected.hostname && allow_auto_rename;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;
    let last_seen = last_seen_text(&params, SecondsFormat::Nanos);
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = if rename {
            resolve_auto_given_name(&mut conn, Some(expected.id), &params.hostname).await?
        } else {
            expected.given_name.clone()
        };
        let update_query = format!(
            r"UPDATE nodes SET
                disco_key = NULLIF(?, ''), endpoints = ?, host_info = ?,
                hostname = CASE WHEN ? = '' THEN hostname ELSE ? END,
                given_name = CASE WHEN COALESCE(given_name, '') = ?
                    THEN NULLIF(?, '') ELSE given_name END,
                approved_routes = CASE WHEN COALESCE(approved_routes, '[]') = ?
                    THEN ? ELSE approved_routes END,
                last_seen = COALESCE(?, last_seen), updated_at = ?
            WHERE id = ? AND {node_identity} = ?
                AND {machine_identity} = ?",
        );
        let result = sqlx::query(&update_query)
            .bind(&params.disco_key)
            .bind(&endpoints)
            .bind(host_info.as_deref())
            .bind(&params.hostname)
            .bind(&params.hostname)
            .bind(&expected.given_name)
            .bind(&given_name)
            .bind(&expected.approved_routes)
            .bind(&approved_routes)
            .bind(&last_seen)
            .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true))
            .bind(expected.id)
            .bind(&expected_node_key)
            .bind(&expected_machine_key)
            .execute(&mut *conn)
            .await
            .map_err(DbError::from);
        match result {
            Ok(result) => {
                if result.rows_affected() == 0 {
                    return Err(DbError::NotFound(format!("node id={}", expected.id)));
                }
                let query = node_select("WHERE id = ?");
                return sqlx::query_as::<_, HeadscaleNodeRow>(&query)
                    .bind(expected.id)
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(map_not_found);
            }
            Err(error) => {
                if !(rename && is_given_name_unique_violation(&error)) {
                    return Err(map_non_retry_write_err(error));
                }
            }
        }
    }
    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

#[cfg(feature = "postgres-sqlx")]
/// Persist client map fields without rewriting ownership, expiry, auth-key
/// references, IP assignments, tags or registration identity.
pub async fn update_postgres_runtime_state(
    pool: &PgPool,
    expected: &HeadscaleNodeRow,
    mut params: CreateParams,
    allow_auto_rename: bool,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let expected_node_key =
        crate::stored_text::key_for_write(&expected.node_key, PublicKeyKind::Node)?;
    let expected_machine_key =
        crate::stored_text::key_for_write(&expected.machine_key, PublicKeyKind::Machine)?;
    let node_identity = key_identity_sql("node_key", PublicKeyKind::Node);
    let machine_identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    if params.node_key != expected_node_key || params.machine_key != expected_machine_key {
        return Err(DbError::Constraint(
            "map update cannot change node or machine key".into(),
        ));
    }
    let mut conn = pool.acquire().await?;
    let rename =
        !params.hostname.is_empty() && params.hostname != expected.hostname && allow_auto_rename;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;
    let last_seen = last_seen_text(&params, SecondsFormat::Micros);
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = if rename {
            resolve_postgres_auto_given_name(&mut conn, Some(expected.id), &params.hostname).await?
        } else {
            expected.given_name.clone()
        };
        let mut attempt = conn.begin().await?;
        let update_query = format!(
            r"UPDATE nodes SET
                disco_key = NULLIF($1, ''), endpoints = $2, host_info = $3,
                hostname = CASE WHEN $4 = '' THEN hostname ELSE $4 END,
                given_name = CASE WHEN COALESCE(given_name, '') = $5
                    THEN NULLIF($6, '') ELSE given_name END,
                approved_routes = CASE WHEN COALESCE(approved_routes, '[]') = $7
                    THEN $8 ELSE approved_routes END,
                last_seen = COALESCE($9::TIMESTAMPTZ, last_seen),
                updated_at = $10::TIMESTAMPTZ
            WHERE id = $11 AND {node_identity} = $12
                AND {machine_identity} = $13",
        );
        let result = sqlx::query(&update_query)
            .bind(&params.disco_key)
            .bind(&endpoints)
            .bind(host_info.as_deref())
            .bind(&params.hostname)
            .bind(&expected.given_name)
            .bind(&given_name)
            .bind(&expected.approved_routes)
            .bind(&approved_routes)
            .bind(&last_seen)
            .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true))
            .bind(expected.id)
            .bind(&expected_node_key)
            .bind(&expected_machine_key)
            .execute(&mut *attempt)
            .await
            .map_err(DbError::from);
        match result {
            Ok(result) => {
                attempt.commit().await?;
                if result.rows_affected() == 0 {
                    return Err(DbError::NotFound(format!("node id={}", expected.id)));
                }
                let query = postgres_node_select("WHERE id = $1");
                return sqlx::query_as::<_, HeadscaleNodeRow>(&query)
                    .bind(expected.id)
                    .fetch_one(&mut *conn)
                    .await
                    .map_err(map_not_found);
            }
            Err(error) => {
                attempt.rollback().await?;
                if !(rename && is_given_name_unique_violation(&error)) {
                    return Err(map_non_retry_write_err(error));
                }
            }
        }
    }
    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<HeadscaleNodeRow> {
    let query = node_select("WHERE id = ?");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_node_key(pool: &SqlitePool, node_key: &str) -> Result<HeadscaleNodeRow> {
    let node_key = crate::stored_text::key_for_write(node_key, PublicKeyKind::Node)?;
    let identity = key_identity_sql("node_key", PublicKeyKind::Node);
    let query = node_select(&format!("WHERE {identity} = ? ORDER BY id LIMIT 1"));
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(node_key)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_machine_key(pool: &SqlitePool, machine_key: &str) -> Result<HeadscaleNodeRow> {
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = node_select(&format!("WHERE {identity} = ? ORDER BY id LIMIT 1"));
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

/// All live ownership candidates for registration on one machine. The first
/// row lookup remains available for Go-compatible database lookup semantics;
/// auth decisions must inspect the complete ownership set.
pub async fn list_by_machine_key(
    pool: &SqlitePool,
    machine_key: &str,
) -> Result<Vec<HeadscaleNodeRow>> {
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = node_select(&format!("WHERE {identity} = ? ORDER BY id"));
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn get_by_machine_key_and_user(
    pool: &SqlitePool,
    machine_key: &str,
    user_id: i64,
) -> Result<HeadscaleNodeRow> {
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = node_select(&format!(
        "WHERE {identity} = ? AND user_id = ? ORDER BY id LIMIT 1"
    ));
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
    let query = node_select("WHERE user_id = ? AND hostname = ? ORDER BY id LIMIT 1");
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
    let query = postgres_node_select("WHERE id = $1");
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
    let node_key = crate::stored_text::key_for_write(node_key, PublicKeyKind::Node)?;
    let identity = key_identity_sql("node_key", PublicKeyKind::Node);
    let query = postgres_node_select(&format!("WHERE {identity} = $1 ORDER BY id LIMIT 1"));
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
pub async fn list_postgres_by_machine_key(
    pool: &PgPool,
    machine_key: &str,
) -> Result<Vec<HeadscaleNodeRow>> {
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = postgres_node_select(&format!("WHERE {identity} = $1 ORDER BY id"));
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(machine_key)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_machine_key_on_connection(
    conn: &mut PgConnection,
    machine_key: &str,
) -> Result<HeadscaleNodeRow> {
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = postgres_node_select(&format!("WHERE {identity} = $1 ORDER BY id LIMIT 1"));
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
    let machine_key = crate::stored_text::key_for_write(machine_key, PublicKeyKind::Machine)?;
    let identity = key_identity_sql("machine_key", PublicKeyKind::Machine);
    let query = postgres_node_select(&format!(
        "WHERE {identity} = $1 AND user_id = $2 ORDER BY id LIMIT 1"
    ));
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
    let query = postgres_node_select("WHERE user_id = $1 AND hostname = $2 ORDER BY id LIMIT 1");
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
    let mut conn = pool.acquire().await?;
    update_from_auth_path_on_connection(&mut conn, id, params).await
}

pub async fn update_from_auth_path_on_connection(
    conn: &mut SqliteConnection,
    id: i64,
    mut params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let retry_auto_given_name = params.given_name.is_empty();
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = auth_path_given_name(conn, id, &params).await?;
        match update_from_auth_path_with_given_name(conn, id, &params, &given_name).await {
            Ok(node) => return Ok(node),
            Err(e) if retry_auto_given_name && is_given_name_unique_violation(&e) => {}
            Err(e) => return Err(map_non_retry_write_err(e)),
        }
    }

    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

async fn update_from_auth_path_with_given_name(
    conn: &mut SqliteConnection,
    id: i64,
    params: &CreateParams,
    given_name: &str,
) -> Result<HeadscaleNodeRow> {
    let tags = normalize_tags(params.tags.clone());
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let ipv4 = crate::stored_text::optional_address(params.ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(params.ipv6.as_deref())?;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;
    let now = now_unix();
    let last_seen = last_seen_text(params, SecondsFormat::Nanos);
    let expiry = expiry_text(params, SecondsFormat::Nanos);
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
            expiry = ?,
            last_seen = ?,
            approved_routes = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ?
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(host_info.as_deref())
    .bind(&ipv4)
    .bind(&ipv6)
    .bind(&params.hostname)
    .bind(given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(expiry)
    .bind(last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(DbError::from)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    let query = node_select("WHERE id = ?");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
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
    mut params: CreateParams,
) -> Result<HeadscaleNodeRow> {
    params.canonicalize_keys()?;
    let retry_auto_given_name = params.given_name.is_empty();
    for _ in 0..AUTO_GIVEN_NAME_RETRY_LIMIT {
        let given_name = auth_path_postgres_given_name(conn, id, &params).await?;
        // A failed INSERT/UPDATE aborts a PostgreSQL transaction. A savepoint
        // lets generated-name retries proceed inside the enclosing registration.
        let mut attempt = conn.begin().await?;
        let result =
            update_postgres_from_auth_path_with_given_name(&mut attempt, id, &params, &given_name)
                .await;
        match result {
            Ok(node) => {
                attempt.commit().await?;
                return Ok(node);
            }
            Err(error) => {
                attempt.rollback().await?;
                if !(retry_auto_given_name && is_given_name_unique_violation(&error)) {
                    return Err(map_non_retry_write_err(error));
                }
            }
        }
    }

    Err(DbError::General(NodeError::NameNotUnique.to_string()))
}

#[cfg(feature = "postgres-sqlx")]
async fn update_postgres_from_auth_path_with_given_name(
    conn: &mut PgConnection,
    id: i64,
    params: &CreateParams,
    given_name: &str,
) -> Result<HeadscaleNodeRow> {
    let tags = normalize_tags(params.tags.clone());
    let user_id = tag_owned_user_id(params.user_id, &tags);
    let ipv4 = crate::stored_text::optional_address(params.ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(params.ipv6.as_deref())?;
    let endpoints = json_array(&crate::stored_json::endpoint_values(&params.endpoints)?)?;
    let host_info = host_info_for_write(&params.host_info)?;
    let tags = json_array(&tags)?;
    let approved_routes = json_array(&crate::stored_json::prefix_values(&params.approved_routes)?)?;
    let now = now_unix();
    let last_seen = last_seen_text(params, SecondsFormat::Micros);
    let expiry = expiry_text(params, SecondsFormat::Micros);
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
            expiry = $14::TIMESTAMPTZ,
            last_seen = $15::TIMESTAMPTZ,
            approved_routes = $16,
            updated_at = to_timestamp(($17::BIGINT)::DOUBLE PRECISION)
        WHERE id = $18
        ",
    )
    .bind(&params.machine_key)
    .bind(&params.node_key)
    .bind(&params.disco_key)
    .bind(&endpoints)
    .bind(host_info.as_deref())
    .bind(&ipv4)
    .bind(&ipv6)
    .bind(&params.hostname)
    .bind(given_name)
    .bind(user_id)
    .bind(&params.register_method)
    .bind(&tags)
    .bind(params.auth_key_id)
    .bind(expiry)
    .bind(last_seen)
    .bind(&approved_routes)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(DbError::from)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    let query = postgres_node_select("WHERE id = $1");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select("ORDER BY id");
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
        "WHERE id IN ({}) ORDER BY id",
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
        node_select("WHERE id != ? ORDER BY id")
    } else {
        node_select(&format!(
            "WHERE id != ? AND id IN ({}) ORDER BY id",
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
        "WHERE auth_key_id IN (SELECT id FROM pre_auth_keys WHERE ephemeral = 1)
         ORDER BY id",
    );
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn list_by_user(pool: &SqlitePool, user_id: i64) -> Result<Vec<HeadscaleNodeRow>> {
    let query = node_select("WHERE user_id = ? ORDER BY id");
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
    let query = postgres_node_select("ORDER BY id");
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

    let query = postgres_node_select("WHERE id = ANY($1) ORDER BY id");
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
        postgres_node_select("WHERE id != $1 ORDER BY id")
    } else {
        postgres_node_select("WHERE id != $1 AND id = ANY($2) ORDER BY id")
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
        "WHERE auth_key_id IN (SELECT id FROM pre_auth_keys WHERE ephemeral = TRUE)
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
    let query = postgres_node_select("WHERE user_id = $1 ORDER BY id");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

pub async fn set_tags(pool: &SqlitePool, id: i64, tags: Vec<String>) -> Result<HeadscaleNodeRow> {
    let tags = normalize_tags(tags);
    let clear_user_id = !tags.is_empty();
    let tags = json_array(&tags)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            user_id = CASE WHEN ? THEN NULL ELSE user_id END,
            tags = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ?
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
    let clear_user_id = !tags.is_empty();
    let tags = json_array(&tags)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            user_id = CASE WHEN $1 THEN NULL ELSE user_id END,
            tags = $2,
            updated_at = to_timestamp(($3::BIGINT)::DOUBLE PRECISION)
        WHERE id = $4
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
        WHERE given_name = ? AND id != ?
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
        WHERE id = ?
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
        WHERE given_name = $1 AND id != $2
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
        WHERE id = $3
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

/// Persist the typed route vector already computed by policy auto-approval.
/// This path does not expand a single default route into the admin exit pair
/// or re-read unrelated columns after the write. The live batch is published
/// before these per-node writes, following Go autoApproveNodes ordering.
pub async fn save_policy_approved_routes(
    pool: &SqlitePool,
    id: i64,
    routes: &[String],
) -> Result<()> {
    let routes = json_array(&crate::stored_json::prefix_values(routes)?)?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    let affected = sqlx::query("UPDATE nodes SET approved_routes = ?, updated_at = ? WHERE id = ?")
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
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn save_postgres_policy_approved_routes(
    pool: &PgPool,
    id: i64,
    routes: &[String],
) -> Result<()> {
    let routes = json_array(&crate::stored_json::prefix_values(routes)?)?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let affected = sqlx::query(
        "UPDATE nodes SET approved_routes = $1, updated_at = $2::TIMESTAMPTZ WHERE id = $3",
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
    Ok(())
}

pub async fn set_approved_routes(
    pool: &SqlitePool,
    id: i64,
    routes: Vec<String>,
) -> Result<HeadscaleNodeRow> {
    let routes = json_array(&normalize_approved_routes(&routes)?)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET approved_routes = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ?
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
    let routes = json_array(&normalize_approved_routes(&routes)?)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET approved_routes = $1, updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3
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
    let mut host_info = row.try_host_info_value()?;
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

    let host_info = host_info_for_write(&host_info)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET host_info = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ?
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
    let mut host_info = row.try_host_info_value()?;
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

    let host_info = host_info_for_write(&host_info)?;
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET host_info = $1, updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3
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
    let precise = expiry
        .map(|seconds| {
            DateTime::from_timestamp(seconds, 0)
                .ok_or_else(|| DbError::General("expiry out of range".into()))
        })
        .transpose()?;
    set_expiry_precise(pool, id, precise).await
}

pub async fn set_expiry_precise(
    pool: &SqlitePool,
    id: i64,
    expiry: Option<DateTime<Utc>>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let expiry = expiry.map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = ?,
            updated_at = datetime(?, 'unixepoch')
        WHERE id = ?
        ",
    )
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
    let precise = expiry
        .map(|seconds| {
            DateTime::from_timestamp(seconds, 0)
                .ok_or_else(|| DbError::General("expiry out of range".into()))
        })
        .transpose()?;
    set_postgres_expiry_precise(pool, id, precise).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_expiry_precise(
    pool: &PgPool,
    id: i64,
    expiry: Option<DateTime<Utc>>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_postgres_expiry_precise_on_connection(&mut conn, id, expiry).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_expiry_on_connection(
    conn: &mut PgConnection,
    id: i64,
    expiry: Option<i64>,
) -> Result<HeadscaleNodeRow> {
    let precise = expiry
        .map(|seconds| {
            DateTime::from_timestamp(seconds, 0)
                .ok_or_else(|| DbError::General("expiry out of range".into()))
        })
        .transpose()?;
    set_postgres_expiry_precise_on_connection(conn, id, precise).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_expiry_precise_on_connection(
    conn: &mut PgConnection,
    id: i64,
    expiry: Option<DateTime<Utc>>,
) -> Result<HeadscaleNodeRow> {
    let now = now_unix();
    let expiry = expiry.map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            expiry = $1::TIMESTAMPTZ,
            updated_at = to_timestamp(($2::BIGINT)::DOUBLE PRECISION)
        WHERE id = $3
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
        WHERE id = ?
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

/// Persist a stream disconnect at full timestamp precision. This deliberately
/// updates only LastSeen and UpdatedAt, avoiding a full node-row rewrite.
pub async fn persist_last_seen_at(pool: &SqlitePool, id: i64, at: &DateTime<Utc>) -> Result<()> {
    let timestamp = at.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let affected = sqlx::query(
        "UPDATE nodes SET last_seen = CASE WHEN last_seen IS NULL OR julianday(last_seen) <= julianday(?) THEN ? ELSE last_seen END, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn persist_postgres_last_seen_at(
    pool: &PgPool,
    id: i64,
    at: &DateTime<Utc>,
) -> Result<()> {
    let mut conn = pool.acquire().await?;
    persist_postgres_last_seen_at_on_connection(&mut conn, id, at).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn persist_postgres_last_seen_at_on_connection(
    conn: &mut PgConnection,
    id: i64,
    at: &DateTime<Utc>,
) -> Result<()> {
    let timestamp = at.to_rfc3339_opts(SecondsFormat::Micros, true);
    let affected = sqlx::query(
        "UPDATE nodes SET last_seen = GREATEST(last_seen, $1::TIMESTAMPTZ), updated_at = NOW() WHERE id = $2",
    )
    .bind(timestamp)
    .bind(id)
    .execute(conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("node id={id}")));
    }
    Ok(())
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
        WHERE id = $3
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

/// IP-only updates prepared by an authenticated backfill operation.
#[derive(Clone, Debug)]
pub struct IpAddressUpdate {
    pub node_id: i64,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

/// Commit the full backfill together. A failure leaves all node rows unchanged;
/// allocator reservations are deliberately owned by the allocator, as in Go.
pub async fn set_ip_addresses_batch(
    pool: &SqlitePool,
    mut updates: Vec<IpAddressUpdate>,
) -> Result<Vec<HeadscaleNodeRow>> {
    for update in &mut updates {
        update.ipv4 = crate::stored_text::optional_address(update.ipv4.as_deref())?;
        update.ipv6 = crate::stored_text::optional_address(update.ipv6.as_deref())?;
    }
    let mut transaction = pool.begin().await?;
    let mut rows = Vec::with_capacity(updates.len());
    for update in updates {
        match set_ip_addresses_on_connection(
            &mut transaction,
            update.node_id,
            update.ipv4,
            update.ipv6,
        )
        .await
        {
            Ok(row) => rows.push(row),
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        }
    }
    transaction.commit().await?;
    Ok(rows)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_ip_addresses_batch(
    pool: &PgPool,
    mut updates: Vec<IpAddressUpdate>,
) -> Result<Vec<HeadscaleNodeRow>> {
    for update in &mut updates {
        update.ipv4 = crate::stored_text::optional_address(update.ipv4.as_deref())?;
        update.ipv6 = crate::stored_text::optional_address(update.ipv6.as_deref())?;
    }
    let mut transaction = pool.begin().await?;
    let mut rows = Vec::with_capacity(updates.len());
    for update in updates {
        match set_postgres_ip_addresses_on_connection(
            &mut transaction,
            update.node_id,
            update.ipv4,
            update.ipv6,
        )
        .await
        {
            Ok(row) => rows.push(row),
            Err(error) => {
                transaction.rollback().await?;
                return Err(error);
            }
        }
    }
    transaction.commit().await?;
    Ok(rows)
}

pub async fn set_ip_addresses(
    pool: &SqlitePool,
    id: i64,
    ipv4: Option<String>,
    ipv6: Option<String>,
) -> Result<HeadscaleNodeRow> {
    let mut conn = pool.acquire().await?;
    set_ip_addresses_on_connection(&mut conn, id, ipv4, ipv6).await
}

pub async fn set_ip_addresses_on_connection(
    conn: &mut SqliteConnection,
    id: i64,
    ipv4: Option<String>,
    ipv6: Option<String>,
) -> Result<HeadscaleNodeRow> {
    let ipv4 = crate::stored_text::optional_address(ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(ipv6.as_deref())?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            ipv4 = ?,
            ipv6 = ?,
            updated_at = ?
        WHERE id = ?
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
    let query = node_select("WHERE id = ?");
    sqlx::query_as::<_, HeadscaleNodeRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(DbError::from)
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
    let ipv4 = crate::stored_text::optional_address(ipv4.as_deref())?;
    let ipv6 = crate::stored_text::optional_address(ipv6.as_deref())?;
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let affected = sqlx::query(
        "
        UPDATE nodes
        SET
            ipv4 = $1,
            ipv6 = $2,
            updated_at = $3::TIMESTAMPTZ
        WHERE id = $4
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
        WHERE id = ?
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
        WHERE id = $3
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

/// Go DeleteNode deletes the authoritative cached ID without requiring an
/// affected row. An already absent SQL row is still a successful deletion.
pub async fn destroy_cached_node(pool: &SqlitePool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM nodes WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await
        .map_err(DbError::from)?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_cached_node(pool: &PgPool, id: i64) -> Result<()> {
    sqlx::query("DELETE FROM nodes WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(DbError::from)?;
    Ok(())
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

fn is_given_name_unique_violation(e: &DbError) -> bool {
    let DbError::Sqlx(sqlx::Error::Database(db)) = e else {
        return false;
    };
    if !db.is_unique_violation() {
        return false;
    }

    db.constraint() == Some("idx_nodes_given_name")
        || db.message().contains("idx_nodes_given_name")
        || db.message().contains("nodes.given_name")
}

fn map_non_retry_write_err(e: DbError) -> DbError {
    match e {
        DbError::Sqlx(e) => map_sqlx_err(e),
        e => e,
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
    use std::collections::BTreeSet;

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
            machine_key: "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
                .into(),
            node_key: "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
                .into(),
            disco_key: "discokey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
                .into(),
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
            expiry_precise: None,
            last_seen: Some(1_700_000_000),
            last_seen_precise: None,
            approved_routes: vec!["10.0.0.0/24".into()],
        }
    }

    fn unique_node_params(
        user_id: i64,
        auth_key_id: i64,
        index: usize,
        hostname: &str,
        given_name: &str,
    ) -> CreateParams {
        let mut params = node_params(user_id, auth_key_id);
        params.machine_key = format!("mkey:{index:064x}");
        params.node_key = format!("nodekey:{index:064x}");
        params.disco_key = format!("discokey:{index:064x}");
        params.hostname = hostname.into();
        params.given_name = given_name.into();
        params.host_info = json!({
            "Hostname": hostname,
            "OS": "linux",
        });
        params.ipv4 = Some(format!("100.64.0.{}", index + 1));
        params.ipv6 = Some(format!("fd7a:115c:a1e0::{}", index + 1));
        params
    }

    fn assert_foreign_key_violation(err: DbError) {
        match err {
            DbError::Sqlx(sqlx::Error::Database(db)) => {
                assert!(
                    db.is_foreign_key_violation(),
                    "expected foreign key violation, got database error: {db}"
                );
            }
            other => panic!("expected foreign key violation, got {other:?}"),
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
        assert_eq!(
            node.machine_key,
            "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
        assert_eq!(
            node.node_key,
            "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
        assert_eq!(
            node.disco_key,
            "discokey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
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
        assert_eq!(
            raw.get::<String, _>("machine_key"),
            "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
        assert_eq!(
            raw.get::<String, _>("node_key"),
            "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
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
        compound_suffix_params.machine_key =
            "mkey:5c2900af3eb01230d2c7425595ad23d2d29a03cc61688063ae97296f4b6d8f65".into();
        compound_suffix_params.node_key =
            "nodekey:5c2900af3eb01230d2c7425595ad23d2d29a03cc61688063ae97296f4b6d8f65".into();
        compound_suffix_params.disco_key =
            "discokey:5c2900af3eb01230d2c7425595ad23d2d29a03cc61688063ae97296f4b6d8f65".into();
        compound_suffix_params.ipv4 = Some("100.64.0.22".into());
        compound_suffix_params.ipv6 = Some("fd7a:115c:a1e0::22".into());
        compound_suffix_params.hostname = "Peer.localdomain.local".into();
        compound_suffix_params.given_name.clear();
        let compound_suffix = create(db.pool(), compound_suffix_params).await.unwrap();
        assert_eq!(compound_suffix.given_name, "peer");

        let mut duplicate_params = node_params(user_id, auth_key_id);
        duplicate_params.machine_key =
            "mkey:6e06b550fd9e124cdb62b306502fdd071eebdc666f6d22fac1f18e94b53b3302".into();
        duplicate_params.node_key =
            "nodekey:6e06b550fd9e124cdb62b306502fdd071eebdc666f6d22fac1f18e94b53b3302".into();
        duplicate_params.disco_key =
            "discokey:6e06b550fd9e124cdb62b306502fdd071eebdc666f6d22fac1f18e94b53b3302".into();
        duplicate_params.ipv4 = Some("100.64.0.2".into());
        duplicate_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        duplicate_params.hostname = "Peer.One!".into();
        duplicate_params.given_name.clear();
        let duplicate = create(db.pool(), duplicate_params).await.unwrap();
        assert_eq!(duplicate.given_name, "peer-one-1");

        let mut empty_params = node_params(user_id, auth_key_id);
        empty_params.machine_key =
            "mkey:758a32d33c8c7b82b007d732f513655d4150aeac98c6718fdcaf3d4486163940".into();
        empty_params.node_key =
            "nodekey:758a32d33c8c7b82b007d732f513655d4150aeac98c6718fdcaf3d4486163940".into();
        empty_params.disco_key =
            "discokey:758a32d33c8c7b82b007d732f513655d4150aeac98c6718fdcaf3d4486163940".into();
        empty_params.ipv4 = Some("100.64.0.3".into());
        empty_params.ipv6 = Some("fd7a:115c:a1e0::3".into());
        empty_params.hostname = "!!!".into();
        empty_params.given_name.clear();
        let empty = create(db.pool(), empty_params).await.unwrap();
        assert_eq!(empty.given_name, "node");
    }

    #[tokio::test]
    async fn concurrent_create_auto_given_names_are_unique_like_headscale_go() {
        const NODE_COUNT: usize = 20;

        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;

        let mut tasks = Vec::with_capacity(NODE_COUNT);
        for index in 0..NODE_COUNT {
            let pool = db.pool().clone();
            let params = unique_node_params(user_id, auth_key_id, index, "laptop", "");
            tasks.push(tokio::spawn(async move { create(&pool, params).await }));
        }

        let mut names = BTreeSet::new();
        for task in tasks {
            let node = task.await.unwrap().unwrap();
            assert!(
                names.insert(node.given_name),
                "concurrent create returned duplicate GivenName"
            );
        }

        assert_eq!(names.len(), NODE_COUNT);
        for index in 0..NODE_COUNT {
            let expected = if index == 0 {
                "laptop".to_string()
            } else {
                format!("laptop-{index}")
            };
            assert!(
                names.contains(&expected),
                "missing expected GivenName {expected}, got {names:?}"
            );
        }
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
        duplicate_params.machine_key =
            "mkey:62783493c5a3656fc94372ec12676a490f76dbefe972187a2d13cf2ed62ac0e4".into();
        duplicate_params.node_key =
            "nodekey:62783493c5a3656fc94372ec12676a490f76dbefe972187a2d13cf2ed62ac0e4".into();
        duplicate_params.disco_key =
            "discokey:62783493c5a3656fc94372ec12676a490f76dbefe972187a2d13cf2ed62ac0e4".into();
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
        second_params.machine_key =
            "mkey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        second_params.node_key =
            "nodekey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        second_params.disco_key =
            "discokey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
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
        ephemeral_params.machine_key =
            "mkey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
        ephemeral_params.node_key =
            "nodekey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
        ephemeral_params.disco_key =
            "discokey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
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
    async fn fractional_expiry_survives_database_read_and_auth_path_update() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();
        let precise = DateTime::from_timestamp(4_102_444_800, 123_456_789).unwrap();

        let expired = set_expiry_precise(db.pool(), node.id, Some(precise))
            .await
            .unwrap();
        assert_eq!(expired.expiry, Some(4_102_444_800));
        assert_eq!(
            expired.expiry_text.as_deref(),
            Some("2100-01-01T00:00:00.123456789Z")
        );
        assert_eq!(
            get_by_id(db.pool(), node.id).await.unwrap().expiry_text,
            expired.expiry_text
        );

        let mut params = node_params(user_id, auth_key_id);
        params.expiry_precise = Some(precise);
        let updated = update_from_auth_path(db.pool(), node.id, params)
            .await
            .unwrap();
        assert_eq!(updated.expiry_text, expired.expiry_text);
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
    async fn create_and_update_enforce_user_fk_except_tag_owned_nodes() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;

        let mut missing_user = node_params(user_id, auth_key_id);
        missing_user.user_id = Some(999);
        assert_foreign_key_violation(create(db.pool(), missing_user).await.unwrap_err());

        let owned = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut update_missing_user = node_params(user_id, auth_key_id);
        update_missing_user.user_id = Some(999);
        assert_foreign_key_violation(
            update_from_auth_path(db.pool(), owned.id, update_missing_user)
                .await
                .unwrap_err(),
        );
        assert_eq!(
            get_by_id(db.pool(), owned.id).await.unwrap().user_id,
            Some(user_id)
        );

        let mut tagged_missing_user = node_params(user_id, auth_key_id);
        tagged_missing_user.user_id = Some(999);
        tagged_missing_user.tags = vec!["tag:server".into()];
        let tagged = update_from_auth_path(db.pool(), owned.id, tagged_missing_user)
            .await
            .unwrap();
        assert_eq!(tagged.user_id, None);
        assert_eq!(tagged.tag_list(), vec!["tag:server"]);
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
        params.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        params.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
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
        assert_eq!(
            updated.machine_key,
            "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
        );
        assert_eq!(
            updated.node_key,
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c"
        );
        assert_eq!(
            updated.disco_key,
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c"
        );
        assert_eq!(updated.endpoint_list(), vec!["198.51.100.10:41641"]);
        assert_eq!(updated.given_name, "alice-reauth");
        assert_eq!(updated.user_id, Some(user_id));
        assert_eq!(updated.auth_key_id, None);
        assert_eq!(updated.register_method, REGISTER_METHOD_OIDC);
        assert!(updated.tag_list().is_empty());
        // Go expands exit routes only in the gRPC SetApprovedRoutes handler;
        // an auth-path update stores the routes it is given.
        assert_eq!(updated.approved_route_list(), vec!["::/0"]);
        assert_eq!(updated.created_at, original.created_at);
        assert!(updated.updated_at >= original.updated_at);
        assert_eq!(
            get_by_machine_key_and_user(
                db.pool(),
                "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a",
                user_id
            )
            .await
            .unwrap()
            .node_key,
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c"
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
        params.node_key =
            "nodekey:717d0d99ce56850b0bb67d34757e91392f6e4d4bca19c55ec03a33da4c532f7e".into();
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
        params.node_key =
            "nodekey:802dfc550b52a9827d343460aeb8a0aa0568fd9c6ccf548a53cef8c93e09decf".into();
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
        second_params.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let mut reauth_params = node_params(user_id, auth_key_id);
        reauth_params.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        reauth_params.node_key =
            "nodekey:d63d35a58aac36961c316280b96e7f5d8d904735f1349123a6b0b9339194032c".into();
        reauth_params.disco_key =
            "discokey:d63d35a58aac36961c316280b96e7f5d8d904735f1349123a6b0b9339194032c".into();
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
    async fn concurrent_update_from_auth_path_auto_given_names_are_unique() {
        const NODE_COUNT: usize = 12;

        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;

        let mut node_ids = Vec::with_capacity(NODE_COUNT);
        for index in 0..NODE_COUNT {
            let params = unique_node_params(
                user_id,
                auth_key_id,
                index,
                &format!("phone-{index}"),
                &format!("phone-{index}"),
            );
            node_ids.push(create(db.pool(), params).await.unwrap().id);
        }

        let mut tasks = Vec::with_capacity(NODE_COUNT);
        for (index, id) in node_ids.into_iter().enumerate() {
            let pool = db.pool().clone();
            let mut params = unique_node_params(user_id, auth_key_id, index, "laptop", "");
            params.node_key = format!("nodekey:{:064x}", index + 1_000);
            params.disco_key = format!("discokey:{:064x}", index + 1_000);
            tasks.push(tokio::spawn(async move {
                update_from_auth_path(&pool, id, params).await
            }));
        }

        let mut names = BTreeSet::new();
        for task in tasks {
            let node = task.await.unwrap().unwrap();
            assert!(
                names.insert(node.given_name),
                "concurrent update returned duplicate GivenName"
            );
        }

        assert_eq!(names.len(), NODE_COUNT);
        for index in 0..NODE_COUNT {
            let expected = if index == 0 {
                "laptop".to_string()
            } else {
                format!("laptop-{index}")
            };
            assert!(
                names.contains(&expected),
                "missing expected GivenName {expected}, got {names:?}"
            );
        }
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
        reauth_params.node_key =
            "nodekey:d63d35a58aac36961c316280b96e7f5d8d904735f1349123a6b0b9339194032c".into();
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
            get_by_node_key(
                db.pool(),
                "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
            )
            .await
            .unwrap()
            .id,
            node.id
        );
        assert_eq!(
            get_by_machine_key(
                db.pool(),
                "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
            )
            .await
            .unwrap()
            .id,
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

        let untagged = set_tags(db.pool(), node.id, Vec::new()).await.unwrap();
        assert!(untagged.tag_list().is_empty());
        assert_eq!(untagged.tags, "[]");
        assert_eq!(untagged.user_id, None);

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
        assert_eq!(routes, vec!["0.0.0.0/0", "::/0"]);
    }

    #[tokio::test]
    async fn approved_routes_sort_and_dedup_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let node = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let routes = set_approved_routes(
            db.pool(),
            node.id,
            vec![
                "192.168.0.0/16".into(),
                "::/0".into(),
                "10.0.0.0/24".into(),
                "10.0.0.0/24".into(),
            ],
        )
        .await
        .unwrap()
        .approved_route_list();

        assert_eq!(
            routes,
            vec!["0.0.0.0/0", "10.0.0.0/24", "192.168.0.0/16", "::/0"]
        );
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
        duplicate_ipv4.machine_key =
            "mkey:d23295e0b6c8db9652e204a7a88e1f8c80666d724ab7c3cb7dbf8dbcf44d0168".into();
        duplicate_ipv4.node_key =
            "nodekey:d23295e0b6c8db9652e204a7a88e1f8c80666d724ab7c3cb7dbf8dbcf44d0168".into();
        duplicate_ipv4.disco_key =
            "discokey:d23295e0b6c8db9652e204a7a88e1f8c80666d724ab7c3cb7dbf8dbcf44d0168".into();
        duplicate_ipv4.hostname = "dup-ipv4".into();
        duplicate_ipv4.given_name = "dup-ipv4".into();
        duplicate_ipv4.ipv6 = Some("fd7a:115c:a1e0::44".into());
        let err = create(db.pool(), duplicate_ipv4).await.unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        let mut duplicate_ipv6 = node_params(user_id, auth_key_id);
        duplicate_ipv6.machine_key =
            "mkey:4a358e137b0207ce4f939b687a50a07c2129d0e5b01fb1758a108cd6aac72764".into();
        duplicate_ipv6.node_key =
            "nodekey:4a358e137b0207ce4f939b687a50a07c2129d0e5b01fb1758a108cd6aac72764".into();
        duplicate_ipv6.disco_key =
            "discokey:4a358e137b0207ce4f939b687a50a07c2129d0e5b01fb1758a108cd6aac72764".into();
        duplicate_ipv6.hostname = "dup-ipv6".into();
        duplicate_ipv6.given_name = "dup-ipv6".into();
        duplicate_ipv6.ipv4 = Some("100.64.0.44".into());
        let err = create(db.pool(), duplicate_ipv6).await.unwrap_err();
        assert!(matches!(err, DbError::General(_)));
    }

    #[tokio::test]
    async fn create_allows_duplicate_live_node_key_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut duplicate = node_params(user_id, auth_key_id);
        duplicate.machine_key =
            "mkey:8cfc6c1810547730098d875f0351f472920846f0d212da9646ff5eba69111c49".into();
        duplicate.disco_key =
            "discokey:8cfc6c1810547730098d875f0351f472920846f0d212da9646ff5eba69111c49".into();
        duplicate.hostname = "duplicate-node-key".into();
        duplicate.given_name = "duplicate-node-key".into();
        duplicate.ipv4 = Some("100.64.0.44".into());
        duplicate.ipv6 = Some("fd7a:115c:a1e0::44".into());
        let duplicate = create(db.pool(), duplicate).await.unwrap();
        assert_ne!(duplicate.id, first.id);
        assert_eq!(duplicate.node_key, first.node_key);
        assert_eq!(
            get_by_node_key(db.pool(), &first.node_key)
                .await
                .unwrap()
                .id,
            first.id,
            "NodeKey lookup should follow headscale-go's first-row ambiguity"
        );

        let mut empty_key = node_params(user_id, auth_key_id);
        empty_key.machine_key =
            "mkey:0304d3b54ec74bd35de4a4a235e69d7690877395e186e84f7026768e15d8dc21".into();
        empty_key.node_key.clear();
        empty_key.disco_key =
            "discokey:0304d3b54ec74bd35de4a4a235e69d7690877395e186e84f7026768e15d8dc21".into();
        empty_key.hostname = "empty-node-key".into();
        empty_key.given_name = "empty-node-key".into();
        empty_key.ipv4 = Some("100.64.0.45".into());
        empty_key.ipv6 = Some("fd7a:115c:a1e0::45".into());
        create(db.pool(), empty_key).await.unwrap();

        let mut second_empty_key = node_params(user_id, auth_key_id);
        second_empty_key.machine_key =
            "mkey:1c3d4711b721b6efc79bc5fd4ca6b14497d7fbb8574e271f3282c484d2f4988c".into();
        second_empty_key.node_key.clear();
        second_empty_key.disco_key =
            "discokey:1c3d4711b721b6efc79bc5fd4ca6b14497d7fbb8574e271f3282c484d2f4988c".into();
        second_empty_key.hostname = "second-empty-node-key".into();
        second_empty_key.given_name = "second-empty-node-key".into();
        second_empty_key.ipv4 = Some("100.64.0.46".into());
        second_empty_key.ipv6 = Some("fd7a:115c:a1e0::46".into());
        create(db.pool(), second_empty_key).await.unwrap();
    }

    #[tokio::test]
    async fn update_from_auth_path_allows_duplicate_live_node_key_like_headscale_go() {
        let db = fresh_db().await;
        let user_id = alice_id(&db).await;
        let auth_key_id = auth_key_id(&db, user_id).await;
        let first = create(db.pool(), node_params(user_id, auth_key_id))
            .await
            .unwrap();

        let mut second_params = node_params(user_id, auth_key_id);
        second_params.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.hostname = "bob-laptop".into();
        second_params.given_name = "bob-laptop".into();
        second_params.ipv4 = Some("100.64.0.2".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::2".into());
        let second = create(db.pool(), second_params).await.unwrap();

        let mut duplicate = node_params(user_id, auth_key_id);
        duplicate.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        let duplicate_node_key = first.node_key.clone();
        duplicate.node_key = duplicate_node_key.clone();
        duplicate.disco_key =
            "discokey:f9f6a22c6b99537181fb1fb426bb28ca6520829aa406a7b381b551c261fc08e0".into();
        duplicate.hostname = "duplicate-node-key-update".into();
        duplicate.given_name = "duplicate-node-key-update".into();
        duplicate.ipv4 = Some("100.64.0.47".into());
        duplicate.ipv6 = Some("fd7a:115c:a1e0::47".into());
        let updated = update_from_auth_path(db.pool(), second.id, duplicate)
            .await
            .unwrap();

        assert_eq!(
            get_by_id(db.pool(), second.id).await.unwrap().node_key,
            duplicate_node_key
        );
        assert_eq!(updated.node_key, duplicate_node_key);
        assert_eq!(
            get_by_node_key(db.pool(), &first.node_key)
                .await
                .unwrap()
                .id,
            first.id,
            "NodeKey lookup should keep returning the earliest live row"
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
        second_params.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
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
        second_params.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        second_params.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
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
