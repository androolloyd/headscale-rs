//! `headscale policy {get,set,check}`.
//!
//! The upstream-compatible path uses the gRPC `GetPolicy`, `SetPolicy`,
//! and `CheckPolicy` RPCs by default. Supplying explicit `--server` keeps
//! the legacy admin HTTP behavior, where `check` remains local-only.

use std::path::Path;

use chrono::{DateTime, SecondsFormat, Utc};
use headscale_api::generated::GetPolicyResponse;
use headscale_api::policy::{
    PolicyCheckNode, PolicyCheckNodeSnapshot, PolicyDoc, PolicyUser,
    check_policy_semantics_for_snapshot, parse_hujson_policy,
    warn_policy_tests_at_boot_for_snapshot,
};
use headscale_db::Database;
use serde::Serialize;

use super::client::AdminClient;
use super::grpc_client::GrpcAdminClient;
use super::output::{OutputFormat, print_structured};
use super::{AdminError, DirectPolicyDatabase, PolicyCmd};

/// Input prepared before connection setup or direct-database confirmation.
/// The standalone binary also keeps server-config loading after confirmation.
#[doc(hidden)]
pub struct PreparedPolicyInput {
    body: Option<String>,
    confirmed_direct_access: bool,
    database_settings: PolicyDatabaseSettings,
}

#[derive(Clone, Copy)]
pub(super) struct PolicyDatabaseSettings {
    sqlite_write_ahead_log: bool,
    sqlite_wal_autocheckpoint: i32,
    #[cfg(feature = "postgres-sqlx")]
    postgres: headscale_db::GoPostgresPoolOptions,
}

impl Default for PolicyDatabaseSettings {
    fn default() -> Self {
        Self {
            sqlite_write_ahead_log: true,
            sqlite_wal_autocheckpoint: 1000,
            #[cfg(feature = "postgres-sqlx")]
            postgres: headscale_db::GoPostgresPoolOptions::default(),
        }
    }
}

impl PreparedPolicyInput {
    pub fn read(command: &PolicyCmd) -> Result<Self, AdminError> {
        let body = match command {
            PolicyCmd::Get { .. } => None,
            PolicyCmd::Set { path, .. } | PolicyCmd::Check { path, .. } => {
                Some(read_policy_file(path)?)
            }
        };
        Ok(Self {
            body,
            confirmed_direct_access: false,
            database_settings: PolicyDatabaseSettings::default(),
        })
    }

    pub fn confirm_direct_database_access(&mut self, force: bool) -> Result<(), AdminError> {
        if !self.confirmed_direct_access {
            confirm_direct_database_access(force)?;
            self.confirmed_direct_access = true;
        }
        Ok(())
    }

    pub fn set_sqlite_settings(&mut self, write_ahead_log: bool, wal_autocheckpoint: i32) {
        self.database_settings.sqlite_write_ahead_log = write_ahead_log;
        self.database_settings.sqlite_wal_autocheckpoint = wal_autocheckpoint;
    }

    #[cfg(feature = "postgres-sqlx")]
    pub fn set_postgres_pool_options(&mut self, options: headscale_db::GoPostgresPoolOptions) {
        self.database_settings.postgres = options;
    }

    pub(super) fn into_parts(self) -> (Option<String>, PolicyDatabaseSettings) {
        (self.body, self.database_settings)
    }
}

pub async fn get(client: &AdminClient, _fmt: OutputFormat) -> Result<(), AdminError> {
    let value: serde_json::Value = client.get_json("/policy").await?;
    print_policy_value(&value)?;
    Ok(())
}

pub async fn get_grpc(client: &mut GrpcAdminClient, _fmt: OutputFormat) -> Result<(), AdminError> {
    let response = PolicyOutput::from(client.get_policy().await?);
    print_policy_text(&response.policy);
    Ok(())
}

pub async fn get_direct_db(
    database: &DirectPolicyDatabase,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    get_direct_db_with_settings(database, fmt, PolicyDatabaseSettings::default()).await
}

pub(super) async fn get_direct_db_with_settings(
    database: &DirectPolicyDatabase,
    _fmt: OutputFormat,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    match database {
        DirectPolicyDatabase::Sqlite { path } => get_direct_sqlite(path, settings).await,
        DirectPolicyDatabase::Postgres { url } => get_direct_postgres(url, settings).await,
        DirectPolicyDatabase::Unavailable { reason } => Err(AdminError::Local(reason.clone())),
    }
}

pub async fn set(client: &AdminClient, path: &Path, fmt: OutputFormat) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    set_body(client, &body, fmt).await
}

pub(super) async fn set_body(
    client: &AdminClient,
    body: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    // Local validation before sending — fail fast on garbage.
    check_policy_str(body)?;
    let resp = client.put_text("/policy", body.to_string()).await?;
    if fmt.is_structured() {
        print_structured(fmt, &resp)?;
    } else {
        let applied = resp
            .get("applied")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        println!("Policy applied: {applied}");
        if let Some(note) = resp.get("note").and_then(serde_json::Value::as_str) {
            println!("Note: {note}");
        }
    }
    Ok(())
}

pub async fn set_grpc(
    client: &mut GrpcAdminClient,
    path: &Path,
    _fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    set_grpc_body(client, &body).await
}

pub(super) async fn set_grpc_body(
    client: &mut GrpcAdminClient,
    body: &str,
) -> Result<(), AdminError> {
    client.set_policy(body.to_string()).await?;
    println!("Policy updated.");
    Ok(())
}

pub async fn set_direct_db(
    database: &DirectPolicyDatabase,
    path: &Path,
    _fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    set_direct_db_body(database, &body, PolicyDatabaseSettings::default()).await
}

pub(super) async fn set_direct_db_body(
    database: &DirectPolicyDatabase,
    body: &str,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    match database {
        DirectPolicyDatabase::Sqlite { path } => set_direct_sqlite(path, body, settings).await?,
        DirectPolicyDatabase::Postgres { url } => set_direct_postgres(url, body, settings).await?,
        DirectPolicyDatabase::Unavailable { reason } => {
            return Err(AdminError::Local(reason.clone()));
        }
    };
    println!("Policy updated.");
    Ok(())
}

/// Local-only validation. Reads the file, strips hujson `//` line
/// comments + trailing commas, then ensures the result parses as
/// `serde_json::Value`. The check is intentionally permissive — we
/// don't yet know the full policy schema (#230 lands that), so we
/// only catch byte-level / brace-level garbage.
pub fn check(path: &Path) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    check_body(path, &raw)
}

pub(super) fn check_body(path: &Path, raw: &str) -> Result<(), AdminError> {
    check_policy_str(raw)?;
    println!("Policy at {} parses OK.", path.display());
    Ok(())
}

pub async fn check_grpc(client: &mut GrpcAdminClient, path: &Path) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    check_grpc_body(client, &raw).await
}

pub(super) async fn check_grpc_body(
    client: &mut GrpcAdminClient,
    raw: &str,
) -> Result<(), AdminError> {
    client.check_policy(raw.to_string()).await?;
    println!("Policy is valid");
    Ok(())
}

pub async fn check_direct_db(
    database: &DirectPolicyDatabase,
    path: &Path,
) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    check_direct_db_body(database, &raw, PolicyDatabaseSettings::default()).await
}

pub(super) async fn check_direct_db_body(
    database: &DirectPolicyDatabase,
    raw: &str,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    match database {
        DirectPolicyDatabase::Sqlite { path } => {
            let db = open_policy_database(path, settings).await?;
            validate_sqlite_policy_with_database(db.pool(), raw, DirectPolicyMode::Check).await?;
        }
        DirectPolicyDatabase::Postgres { url } => {
            check_direct_postgres(url, raw, settings).await?;
        }
        DirectPolicyDatabase::Unavailable { reason } => {
            return Err(AdminError::Local(reason.clone()));
        }
    }
    println!("Policy is valid");
    Ok(())
}

pub fn confirm_direct_database_access(force: bool) -> Result<(), AdminError> {
    if force {
        return Ok(());
    }

    if super::confirmation::confirm_action(
        "DO NOT run this command if an instance of headscale is running, are you sure headscale is not running?",
    ) {
        Ok(())
    } else {
        Err(AdminError::Local("command aborted by user".into()))
    }
}

fn read_policy_file(path: &Path) -> Result<String, AdminError> {
    std::fs::read_to_string(path).map_err(|error| {
        let operation = if error.kind() == std::io::ErrorKind::IsADirectory {
            "read"
        } else {
            "open"
        };
        let message = match error.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            std::io::ErrorKind::IsADirectory => "is a directory".to_string(),
            std::io::ErrorKind::NotADirectory => "not a directory".to_string(),
            _ => {
                let mut message = error.to_string();
                if let Some(code) = error.raw_os_error() {
                    let suffix = format!(" (os error {code})");
                    if message.ends_with(&suffix) {
                        message.truncate(message.len() - suffix.len());
                    }
                }
                message
            }
        };
        AdminError::Local(format!(
            "reading policy file: {operation} {}: {message}",
            path.display()
        ))
    })
}

fn print_policy_value(value: &serde_json::Value) -> Result<(), AdminError> {
    let Some(policy) = value.get("policy").filter(|policy| !policy.is_null()) else {
        return Ok(());
    };
    if let Some(policy) = policy.as_str() {
        print_policy_text(policy);
    } else {
        let text = serde_json::to_string_pretty(policy)
            .map_err(|e| AdminError::Decode(format!("serialise policy output: {e}")))?;
        print_policy_text(&text);
    }
    Ok(())
}

fn print_policy_text(policy: &str) {
    println!("{policy}");
}

async fn validate_sqlite_policy_with_database(
    pool: &sqlx::SqlitePool,
    raw: &str,
    mode: DirectPolicyMode,
) -> Result<(), AdminError> {
    let users = headscale_db::users::list(pool).await.map_err(|error| {
        AdminError::Local(format!(
            "{}: {}",
            mode.users_error_context(),
            error.headscale_go_message()
        ))
    })?;
    let identities = policy_users_from_rows(&users)?;
    let nodes = if mode == DirectPolicyMode::Check {
        let rows = headscale_db::headscale_nodes::list(pool)
            .await
            .map_err(|error| {
                AdminError::Local(format!("loading nodes: {}", error.headscale_go_message()))
            })?;
        policy_check_nodes_from_rows(rows, &identities)?
    } else {
        Vec::new()
    };
    validate_direct_policy(raw, &identities, &nodes, mode)
}

fn validate_direct_user_references(
    doc: &PolicyDoc,
    raw: &str,
    users: &[PolicyUser],
) -> Result<(), AdminError> {
    headscale_api::policy::validate_policy_user_references_for_source(doc, raw, users).map_err(
        |error| {
            AdminError::Usage(format!(
                "parsing policy file: validating policy user references: {error}"
            ))
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectPolicyMode {
    Set,
    Check,
}

impl DirectPolicyMode {
    fn users_error_context(self) -> &'static str {
        match self {
            Self::Set => "loading users for policy validation",
            Self::Check => "loading users",
        }
    }
}

fn policy_check_nodes_from_rows(
    rows: Vec<headscale_db::headscale_nodes::HeadscaleNodeRow>,
    users: &[PolicyUser],
) -> Result<Vec<PolicyCheckNodeSnapshot>, AdminError> {
    let users_by_id = users
        .iter()
        .map(|user| (user.id, user))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut seen = std::collections::BTreeSet::new();
    rows.into_iter()
        .map(|row| {
            let id = u64::try_from(row.id)
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| AdminError::Local("invalid persisted node identity".into()))?;
            if !seen.insert(id) {
                return Err(AdminError::Local(
                    "duplicate live node ID in policy snapshot".into(),
                ));
            }
            let tags = row
                .try_tag_list()
                .map_err(|error| AdminError::Local(format!("loading node tags: {error}")))?;
            let host_info = row
                .try_host_info_value()
                .map_err(|error| AdminError::Local(format!("loading node hostinfo: {error}")))?;
            let advertised_routes = host_info
                .get("RoutableIPs")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect();
            let approved_routes = row.try_approved_route_list().map_err(|error| {
                AdminError::Local(format!("loading node route approvals: {error}"))
            })?;
            // Go ListNodes preloads User. An unresolved foreign key does not
            // supply an owner to policy aliases, even when UserID is present.
            // Tagged nodes retain the association for creator metadata; the
            // policy resolver applies tag ownership separately.
            let owner = row
                .user_id
                .map(u64::try_from)
                .transpose()
                .map_err(|_| AdminError::Local("invalid persisted node user identity".into()))?
                .and_then(|id| users_by_id.get(&id).copied());
            let user_id = owner.map(|user| user.id);
            let user = owner.map(|user| {
                if !user.email.is_empty() {
                    user.email.clone()
                } else if !user.name.is_empty() {
                    user.name.clone()
                } else if let Some(provider) = user
                    .provider_identifier
                    .as_ref()
                    .filter(|provider| !provider.is_empty())
                {
                    provider.clone()
                } else {
                    user.id.to_string()
                }
            });
            // Non-null empty text is Go's typed zero Addr. Keep that slot,
            // along with scoped/mapped addresses, instead of treating it as
            // an absent allocation. SQL rows have already been decoded, but
            // validate manual row projections through the same text boundary.
            let addrs = row
                .ipv4
                .into_iter()
                .chain(row.ipv6)
                .map(|address| {
                    headscale_api_acl::go_netip::addr_text(&address)
                        .ok_or_else(|| AdminError::Local("invalid persisted IP address".into()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PolicyCheckNodeSnapshot {
                advertised_routes,
                approved_routes,
                node: PolicyCheckNode {
                    id,
                    user_id,
                    name: row.given_name,
                    user,
                    addrs,
                    tags,
                },
            })
        })
        .collect()
}

fn policy_users_from_rows(
    rows: &[headscale_db::users::UserRow],
) -> Result<Vec<PolicyUser>, AdminError> {
    rows.iter()
        .map(|user| {
            Ok(PolicyUser {
                id: u64::try_from(user.id)
                    .map_err(|_| AdminError::Local("invalid persisted user identity".into()))?,
                name: user.name.clone(),
                email: user.email.clone(),
                provider_identifier: user.provider_identifier.clone(),
            })
        })
        .collect()
}

fn validate_direct_policy(
    raw: &str,
    users: &[PolicyUser],
    nodes: &[PolicyCheckNodeSnapshot],
    mode: DirectPolicyMode,
) -> Result<(), AdminError> {
    let mut doc = if raw.is_empty() {
        PolicyDoc::default()
    } else {
        parse_hujson_policy(raw).map_err(|error| {
            AdminError::Local(format!("parsing policy file: parsing policy: {error}"))
        })?
    };
    validate_direct_user_references(&doc, raw, users)?;
    doc.users = Some(users.to_vec());
    // NewPolicyManager compiles before emitting boot test warnings. Reuse the
    // isolated store's fallible compilation with the same node/route snapshot
    // so constructor errors cannot be persisted by Set or masked in Check.
    headscale_api::policy::compile_policy_for_snapshot(&doc, raw, nodes)
        .map_err(|error| AdminError::Local(format!("parsing policy file: {error}")))?;
    warn_policy_tests_at_boot_for_snapshot(&doc, raw, nodes);
    // Direct Set only constructs the manager with an empty node snapshot,
    // then persists the policy; constructor test failures are warnings. Go's
    // direct Check follows construction with the hard SetPolicy boundary.
    if mode == DirectPolicyMode::Check {
        check_policy_semantics_for_snapshot(&doc, raw, nodes).map_err(AdminError::Local)?;
    }
    Ok(())
}

async fn get_direct_sqlite(
    path: &Path,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    let db = open_policy_database(path, settings).await?;
    let policy = headscale_db::policies::get_latest(db.pool())
        .await
        .map_err(|error| direct_policy_get_error(&error))?
        .ok_or_else(|| {
            AdminError::Local("loading policy from database: acl policy not found".into())
        })?;
    let response = PolicyOutput {
        policy: policy.data,
        updated_at: Some(unix_timestamp_rfc3339(policy.updated_at)),
    };
    print_policy_text(&response.policy);
    Ok(())
}

async fn set_direct_sqlite(
    path: &Path,
    body: &str,
    settings: PolicyDatabaseSettings,
) -> Result<headscale_db::policies::PolicyRow, AdminError> {
    let db = open_policy_database(path, settings).await?;
    validate_sqlite_policy_with_database(db.pool(), body, DirectPolicyMode::Set).await?;
    headscale_db::policies::set(db.pool(), body)
        .await
        .map_err(|error| direct_policy_set_error(&error))
}

#[cfg(feature = "postgres-sqlx")]
async fn get_direct_postgres(
    url: &str,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    let pool = open_postgres_policy_pool(url, settings).await?;
    let policy = headscale_db::policies::get_latest_postgres(&pool)
        .await
        .map_err(|error| direct_policy_get_error(&error))?
        .ok_or_else(|| {
            AdminError::Local("loading policy from database: acl policy not found".into())
        })?;
    let response = PolicyOutput {
        policy: policy.data,
        updated_at: Some(unix_timestamp_rfc3339(policy.updated_at)),
    };
    print_policy_text(&response.policy);
    Ok(())
}

#[cfg(not(feature = "postgres-sqlx"))]
async fn get_direct_postgres(
    _url: &str,
    _settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    Err(postgres_feature_error())
}

#[cfg(feature = "postgres-sqlx")]
async fn set_direct_postgres(
    url: &str,
    body: &str,
    settings: PolicyDatabaseSettings,
) -> Result<headscale_db::policies::PolicyRow, AdminError> {
    let pool = open_postgres_policy_pool(url, settings).await?;
    validate_postgres_policy_with_database(&pool, body, DirectPolicyMode::Set).await?;
    headscale_db::policies::set_postgres(&pool, body)
        .await
        .map_err(|error| direct_policy_set_error(&error))
}

#[cfg(not(feature = "postgres-sqlx"))]
async fn set_direct_postgres(
    _url: &str,
    _body: &str,
    _settings: PolicyDatabaseSettings,
) -> Result<headscale_db::policies::PolicyRow, AdminError> {
    Err(postgres_feature_error())
}

#[cfg(feature = "postgres-sqlx")]
async fn check_direct_postgres(
    url: &str,
    raw: &str,
    settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    let pool = open_postgres_policy_pool(url, settings).await?;
    validate_postgres_policy_with_database(&pool, raw, DirectPolicyMode::Check).await
}

#[cfg(not(feature = "postgres-sqlx"))]
async fn check_direct_postgres(
    _url: &str,
    _raw: &str,
    _settings: PolicyDatabaseSettings,
) -> Result<(), AdminError> {
    Err(postgres_feature_error())
}

#[cfg(feature = "postgres-sqlx")]
async fn validate_postgres_policy_with_database(
    pool: &sqlx::PgPool,
    raw: &str,
    mode: DirectPolicyMode,
) -> Result<(), AdminError> {
    let records = headscale_db::users::list_postgres(pool)
        .await
        .map_err(|error| {
            AdminError::Local(format!(
                "{}: {}",
                mode.users_error_context(),
                error.headscale_go_message()
            ))
        })?;
    let identities = policy_users_from_rows(&records)?;
    let nodes = if mode == DirectPolicyMode::Check {
        let rows = headscale_db::headscale_nodes::list_postgres(pool)
            .await
            .map_err(|error| {
                AdminError::Local(format!("loading nodes: {}", error.headscale_go_message()))
            })?;
        policy_check_nodes_from_rows(rows, &identities)?
    } else {
        Vec::new()
    };
    validate_direct_policy(raw, &identities, &nodes, mode)
}

fn direct_policy_get_error(error: &headscale_db::DbError) -> AdminError {
    AdminError::Local(format!(
        "loading policy from database: {}",
        error.headscale_go_message()
    ))
}

fn direct_policy_set_error(error: &headscale_db::DbError) -> AdminError {
    AdminError::Local(format!(
        "setting ACL policy: {}",
        error.headscale_go_message()
    ))
}

fn direct_policy_database_error(error: &headscale_db::DbError) -> AdminError {
    AdminError::Local(format!(
        "opening database: {}",
        error.headscale_go_message()
    ))
}

fn direct_policy_migration_error(error: headscale_db::DbError) -> AdminError {
    // Database::migrate combines several startup stages. Only these variants
    // identify a Go phase reliably; a generic SQL error may instead come from
    // the version query, schema work or version stamp.
    let message = match error {
        headscale_db::DbError::UnsupportedHeadscaleGoDatabaseVersion(message) => {
            format!("version check: {message}")
        }
        headscale_db::DbError::Migration(error) => format!("migration failed: {error}"),
        error => error.headscale_go_message(),
    };
    AdminError::Local(format!("opening database: {message}"))
}

#[cfg(feature = "postgres-sqlx")]
async fn open_postgres_policy_pool(
    url: &str,
    settings: PolicyDatabaseSettings,
) -> Result<sqlx::PgPool, AdminError> {
    let pool = headscale_db::open_postgres_pool_with_options(url, settings.postgres)
        .await
        .map_err(|error| direct_policy_database_error(&error))?;
    headscale_db::migrate_postgres_foundation(&pool)
        .await
        .map_err(direct_policy_migration_error)?;
    Ok(pool)
}

#[cfg(not(feature = "postgres-sqlx"))]
fn postgres_feature_error() -> AdminError {
    AdminError::Local(
        "direct database policy access for Postgres requires the postgres-sqlx feature".into(),
    )
}

async fn open_policy_database(
    path: &Path,
    settings: PolicyDatabaseSettings,
) -> Result<Database, AdminError> {
    ensure_parent_dir(path)?;
    let url = sqlite_url_for_path(path);
    let options = headscale_db::go_sqlite_open_options(
        settings.sqlite_write_ahead_log,
        settings.sqlite_wal_autocheckpoint,
    )
    .map_err(|error| direct_policy_database_error(&error))?;
    let db = Database::new_with_go_sqlite_options(&url, options)
        .await
        .map_err(|error| direct_policy_database_error(&error))?;
    db.migrate().await.map_err(direct_policy_migration_error)?;
    Ok(db)
}

fn sqlite_url_for_path(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

fn ensure_parent_dir(path: &Path) -> Result<(), AdminError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && std::fs::metadata(parent)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        // Go util.EnsureDir creates missing directories with PermissionFallback
        // (0700), and ignores stat failures other than NotExist at this stage.
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(parent).map_err(|error| {
            let message = if error.kind() == std::io::ErrorKind::PermissionDenied {
                format!(
                    "creating directory failed with permission error: {}",
                    parent.display()
                )
            } else {
                let mut message = error.to_string();
                if let Some(code) = error.raw_os_error() {
                    let suffix = format!(" (os error {code})");
                    if message.ends_with(&suffix) {
                        message.truncate(message.len() - suffix.len());
                    }
                }
                format!("creating directory {}: {message}", parent.display())
            };
            AdminError::Local(format!(
                "opening database: creating directory for sqlite: {message}"
            ))
        })?;
    }
    Ok(())
}

fn timestamp_rfc3339(ts: Option<&prost_types::Timestamp>) -> Option<String> {
    let ts = ts?;
    let nanos = u32::try_from(ts.nanos).ok()?;
    DateTime::<Utc>::from_timestamp(ts.seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn unix_timestamp_rfc3339(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_string(),
        |time| time.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

#[derive(Debug, Serialize)]
struct PolicyOutput {
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

impl From<GetPolicyResponse> for PolicyOutput {
    fn from(response: GetPolicyResponse) -> Self {
        Self {
            policy: response.policy,
            updated_at: timestamp_rfc3339(response.updated_at.as_ref()),
        }
    }
}

/// Run the local-only parse. Exposed so the unit tests can exercise
/// the parser without a file on disk.
pub fn check_policy_str(raw: &str) -> Result<(), AdminError> {
    let stripped = strip_hujson(raw);
    serde_json::from_str::<serde_json::Value>(&stripped)
        .map(|_| ())
        .map_err(|e| AdminError::Local(format!("policy does not parse as (hu)json: {e}")))
}

/// Minimal hujson → JSON pre-processor. Strips `//` line comments,
/// `/* … */` block comments, and trailing commas before `]`/`}`. Good
/// enough for the local syntactic check; the server (or the real
/// editor in #230) owns the semantic validation.
fn strip_hujson(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            out.push(c);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        // Line comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // Skip until newline.
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            // Consume the closing `*/` (or EOF).
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push(b'"');
            i += 1;
            continue;
        }
        // Trailing comma: `,` followed by whitespace then `]` or `}`.
        if c == b',' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                // Drop this comma.
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    String::from_utf8(out).expect("stripping comments preserves UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_line_comment() {
        let s = strip_hujson("{\n  // hello\n  \"a\": 1\n}");
        assert!(!s.contains("hello"));
        assert!(s.contains("\"a\""));
    }

    #[test]
    fn strip_block_comment() {
        let s = strip_hujson("{/* x */\"a\":1}");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn strip_trailing_comma_in_array() {
        let s = strip_hujson("[1,2,3,]");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn strip_trailing_comma_in_object() {
        let s = strip_hujson("{\"a\":1,}");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn preserves_strings_containing_slashes() {
        // The slashes inside the URL string are not the start of a
        // comment — the stripper must not chop them.
        let s = strip_hujson("{\"url\":\"http://x/y//z\"}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["url"], "http://x/y//z");
    }

    #[test]
    fn check_policy_str_accepts_valid() {
        assert!(check_policy_str("{\"acls\":[]}").is_ok());
    }

    #[test]
    fn check_policy_str_rejects_garbage() {
        assert!(check_policy_str("not json {").is_err());
    }

    #[test]
    fn policy_output_formats_timestamp_as_rfc3339() {
        let output = PolicyOutput::from(GetPolicyResponse {
            policy: "{\"acls\":[]}".into(),
            updated_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
        });
        assert_eq!(output.updated_at.as_deref(), Some("2024-01-01T00:00:00Z"));
    }
}
