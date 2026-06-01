#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    HEADSCALE_GO_CURRENT_VERSION, api_keys, check_postgres_health_on_connection,
    migrate_postgres_foundation_on_connection, open_postgres_pool, policies, users,
};
use sqlx::{PgConnection, PgPool};
use std::time::{SystemTime, UNIX_EPOCH};

const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn postgres_foundation_creates_and_stamps_database_versions() -> TestResult {
    let Some(mut schema) = TempSchema::open("database_versions").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let row: (i64, String, bool) = sqlx::query_as(
            "
            SELECT id, version, updated_at IS NOT NULL
            FROM database_versions
            ",
        )
        .fetch_one(&mut schema.conn)
        .await?;

        assert_eq!(row, (1, HEADSCALE_GO_CURRENT_VERSION.to_string(), true));

        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;
        let row: (i64, String, bool) = sqlx::query_as(
            "
            SELECT id, version, updated_at IS NOT NULL
            FROM database_versions
            ",
        )
        .fetch_one(&mut schema.conn)
        .await?;

        assert_eq!(row, (1, HEADSCALE_GO_CURRENT_VERSION.to_string(), true));
        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_foundation_rejects_newer_database_versions_before_migration() -> TestResult {
    let Some(mut schema) = TempSchema::open("reject_newer_database_versions").await? else {
        return Ok(());
    };

    let result = async {
        sqlx::query(
            "
            CREATE TABLE database_versions (
                id BIGINT PRIMARY KEY,
                version TEXT NOT NULL,
                updated_at TIMESTAMPTZ
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.99.0', CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;

        let err = migrate_postgres_foundation_on_connection(&mut schema.conn)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            headscale_db::DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
        ));
        assert!(err.to_string().contains("newer headscale-go"));
        assert!(!postgres_table_exists(&mut schema.conn, "_sqlx_migrations").await?);
        assert!(!postgres_table_exists(&mut schema.conn, "users").await?);

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_foundation_rejects_unsupported_rust_managed_database_version() -> TestResult {
    let Some(mut schema) = TempSchema::open("reject_rust_managed_database_version").await? else {
        return Ok(());
    };

    let result = async {
        sqlx::query(
            "
            CREATE TABLE _sqlx_migrations (
                version BIGINT PRIMARY KEY
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE database_versions (
                id BIGINT PRIMARY KEY,
                version TEXT NOT NULL,
                updated_at TIMESTAMPTZ
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE users (
                id BIGINT PRIMARY KEY
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.99.0', CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;

        let err = migrate_postgres_foundation_on_connection(&mut schema.conn)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            headscale_db::DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
        ));
        assert!(err.to_string().contains("Rust-managed Postgres"));
        assert!(!postgres_table_exists(&mut schema.conn, "policies").await?);

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_foundation_accepts_supported_go_version_history() -> TestResult {
    let Some(mut schema) = TempSchema::open("accept_supported_go_history").await? else {
        return Ok(());
    };

    let result = async {
        sqlx::query(
            "
            CREATE TABLE database_versions (
                id BIGINT PRIMARY KEY,
                version TEXT NOT NULL,
                updated_at TIMESTAMPTZ
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE migrations (
                id TEXT PRIMARY KEY
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.28.0', CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO migrations (id)
            VALUES ('202601121700-migrate-hostinfo-request-tags')
            ",
        )
        .execute(&mut schema.conn)
        .await?;

        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        assert!(postgres_table_exists(&mut schema.conn, "_sqlx_migrations").await?);
        assert!(postgres_table_exists(&mut schema.conn, "users").await?);
        let version: String =
            sqlx::query_scalar("SELECT version FROM database_versions WHERE id = 1")
                .fetch_one(&mut schema.conn)
                .await?;
        assert_eq!(version, HEADSCALE_GO_CURRENT_VERSION);

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_foundation_clears_tagged_node_user_ids_on_go_import() -> TestResult {
    let Some(mut schema) = TempSchema::open("clear_tagged_node_user_ids").await? else {
        return Ok(());
    };

    let result = async {
        sqlx::query(
            "
            CREATE TABLE database_versions (
                id BIGINT PRIMARY KEY,
                version TEXT NOT NULL,
                updated_at TIMESTAMPTZ
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.28.0', CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE migrations (
                id TEXT PRIMARY KEY
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO migrations (id)
            VALUES ('202601121700-migrate-hostinfo-request-tags')
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE users (
                id BIGINT PRIMARY KEY,
                created_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ,
                deleted_at TIMESTAMPTZ,
                name TEXT,
                display_name TEXT,
                email TEXT,
                provider_identifier TEXT,
                provider TEXT,
                profile_pic_url TEXT
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO users
                (id, name, display_name, email, provider, profile_pic_url, created_at, updated_at)
            VALUES
                (10, 'alice', 'Alice', 'alice@example.com', 'cli', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            CREATE TABLE nodes (
                id BIGINT PRIMARY KEY,
                machine_key TEXT,
                node_key TEXT,
                disco_key TEXT,
                endpoints TEXT,
                host_info TEXT,
                ipv4 TEXT,
                ipv6 TEXT,
                hostname TEXT,
                given_name TEXT,
                user_id BIGINT,
                register_method TEXT,
                tags TEXT,
                auth_key_id BIGINT,
                expiry TIMESTAMPTZ,
                last_seen TIMESTAMPTZ,
                approved_routes TEXT,
                created_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ,
                deleted_at TIMESTAMPTZ
            )
            ",
        )
        .execute(&mut schema.conn)
        .await?;
        sqlx::query(
            "
            INSERT INTO nodes
                (id, node_key, hostname, given_name, user_id, tags, created_at, updated_at)
            VALUES
                (1, 'nodekey:tagged', 'tagged', 'tagged', 10, '[\"tag:server\"]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                (2, 'nodekey:untagged', 'untagged', 'untagged', 10, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                (3, 'nodekey:empty-tags', 'empty-tags', 'empty-tags', 10, '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                (4, 'nodekey:null-tags', 'null-tags', 'null-tags', 10, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ",
        )
        .execute(&mut schema.conn)
        .await?;

        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let rows: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT id, user_id FROM nodes ORDER BY id")
                .fetch_all(&mut schema.conn)
                .await?;
        assert_eq!(
            rows,
            vec![(1, None), (2, Some(10)), (3, Some(10)), (4, Some(10))]
        );

        let version: String =
            sqlx::query_scalar("SELECT version FROM database_versions WHERE id = 1")
                .fetch_one(&mut schema.conn)
                .await?;
        assert_eq!(version, HEADSCALE_GO_CURRENT_VERSION);

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_policy_primitives_append_read_and_ignore_deleted_rows() -> TestResult {
    let Some(mut schema) = TempSchema::open("policies").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        assert!(
            policies::get_latest_postgres_on_connection(&mut schema.conn)
                .await?
                .is_none()
        );

        let first = policies::set_postgres_on_connection(
            &mut schema.conn,
            "{\n  // first\n  \"acls\": []\n}",
        )
        .await?;
        let second = policies::set_postgres_on_connection(
            &mut schema.conn,
            "{\n  // second\n  \"acls\": []\n}",
        )
        .await?;

        assert!(second.id > first.id);
        let latest = policies::get_latest_postgres_on_connection(&mut schema.conn)
            .await?
            .expect("latest policy");
        assert_eq!(latest.id, second.id);
        assert_eq!(latest.data, "{\n  // second\n  \"acls\": []\n}");
        assert_eq!(latest.created_at, latest.updated_at);
        assert!(latest.deleted_at.is_none());

        let fetched =
            policies::get_postgres_by_id_on_connection(&mut schema.conn, first.id).await?;
        assert_eq!(fetched.data, "{\n  // first\n  \"acls\": []\n}");

        sqlx::query("UPDATE policies SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(second.id)
            .execute(&mut schema.conn)
            .await?;

        let latest = policies::get_latest_postgres_on_connection(&mut schema.conn)
            .await?
            .expect("latest policy after soft delete");
        assert_eq!(latest.id, first.id);
        assert_eq!(latest.data, "{\n  // first\n  \"acls\": []\n}");
        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_health_check_pings_database() -> TestResult {
    let Some(mut schema) = TempSchema::open("health").await? else {
        return Ok(());
    };

    let result = check_postgres_health_on_connection(&mut schema.conn).await;
    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_user_primitives_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("users").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let alice = users::create_postgres_on_connection(
            &mut schema.conn,
            users::CreateParams {
                name: "alice".into(),
                display_name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                provider_identifier: None,
                provider: "cli".into(),
                profile_pic_url: "https://example.com/alice.png".into(),
            },
        )
        .await?;
        assert_eq!(alice.name, "alice");
        assert_eq!(alice.display(), "Alice Smith");
        assert_eq!(alice.username(), "alice@example.com");
        assert_eq!(alice.provider, "cli");
        assert!(alice.created_at > 0);
        assert_eq!(alice.created_at, alice.updated_at);
        assert!(alice.deleted_at.is_none());

        assert_eq!(
            users::get_postgres_by_id_on_connection(&mut schema.conn, alice.id)
                .await?
                .name,
            "alice"
        );
        assert_eq!(
            users::get_postgres_by_name_on_connection(&mut schema.conn, "alice")
                .await?
                .id,
            alice.id
        );
        assert!(matches!(
            users::create_postgres_on_connection(
                &mut schema.conn,
                users::CreateParams {
                    name: "alice".into(),
                    provider: "cli".into(),
                    ..users::CreateParams::default()
                },
            )
            .await
            .unwrap_err(),
            headscale_db::DbError::General(_)
        ));

        let renamed =
            users::rename_postgres_on_connection(&mut schema.conn, alice.id, "renamed").await?;
        assert_eq!(renamed.name, "renamed");
        users::touch_postgres_by_name_on_connection(&mut schema.conn, "renamed").await?;
        assert_eq!(
            users::list_postgres_on_connection(&mut schema.conn)
                .await?
                .len(),
            1
        );

        users::destroy_postgres_on_connection(&mut schema.conn, renamed.id).await?;
        assert!(
            users::list_postgres_on_connection(&mut schema.conn)
                .await?
                .is_empty()
        );
        assert!(matches!(
            users::destroy_postgres_on_connection(&mut schema.conn, renamed.id)
                .await
                .unwrap_err(),
            headscale_db::DbError::NotFound(_)
        ));

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_oidc_user_primitives_match_upsert_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("oidc_users").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let original = users::create_or_update_oidc_user_postgres_on_connection(
            &mut schema.conn,
            users::OidcUserParams {
                name: "oidc-user".into(),
                email: "old@example.com".into(),
                display_name: "Old Name".into(),
                provider_identifier: "issuer/sub".into(),
                profile_pic_url: "https://example.com/old.png".into(),
            },
        )
        .await?;
        assert_eq!(original.name, "oidc-user");
        assert_eq!(original.provider, "oidc");
        assert_eq!(original.provider_identifier.as_deref(), Some("issuer/sub"));
        assert_eq!(
            users::get_postgres_by_oidc_identifier_on_connection(&mut schema.conn, "issuer/sub")
                .await?
                .id,
            original.id
        );
        assert!(matches!(
            users::rename_postgres_on_connection(&mut schema.conn, original.id, "new-name")
                .await
                .unwrap_err(),
            headscale_db::DbError::General(_)
        ));

        let updated = users::create_or_update_oidc_user_postgres_on_connection(
            &mut schema.conn,
            users::OidcUserParams {
                display_name: "New Name".into(),
                provider_identifier: "issuer/sub".into(),
                ..users::OidcUserParams::default()
            },
        )
        .await?;
        assert_eq!(updated.id, original.id);
        assert_eq!(updated.name, "oidc-user");
        assert_eq!(updated.email, "old@example.com");
        assert_eq!(updated.display_name, "New Name");
        assert_eq!(updated.profile_pic_url, "");

        users::create_postgres_on_connection(
            &mut schema.conn,
            users::CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/a".into()),
                provider: "oidc".into(),
                ..users::CreateParams::default()
            },
        )
        .await?;
        users::create_postgres_on_connection(
            &mut schema.conn,
            users::CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/b".into()),
                provider: "oidc".into(),
                ..users::CreateParams::default()
            },
        )
        .await?;
        assert!(matches!(
            users::get_postgres_by_name_on_connection(&mut schema.conn, "same")
                .await
                .unwrap_err(),
            headscale_db::DbError::General(_)
        ));

        sqlx::query("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(updated.id)
            .execute(&mut schema.conn)
            .await?;
        assert!(matches!(
            users::get_postgres_by_id_on_connection(&mut schema.conn, updated.id)
                .await
                .unwrap_err(),
            headscale_db::DbError::NotFound(_)
        ));

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_api_key_primitives_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("api_keys").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let created = api_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            api_keys::CreateParams { expiration: None },
        )
        .await?;
        assert!(created.plaintext.starts_with(api_keys::API_KEY_PREFIX));
        let rest = created
            .plaintext
            .strip_prefix(api_keys::API_KEY_PREFIX)
            .expect("generated API key prefix");
        assert_eq!(rest.as_bytes()[api_keys::API_KEY_PREFIX_LEN], b'-');
        assert_eq!(created.row.prefix, &rest[..api_keys::API_KEY_PREFIX_LEN]);
        assert_eq!(
            created.row.display_prefix(),
            format!("{}{}-***", api_keys::API_KEY_PREFIX, created.row.prefix)
        );
        assert!(created.row.created_at > 0);
        assert!(created.row.last_seen.is_none());

        assert!(
            api_keys::validate_postgres_on_connection(&mut schema.conn, &created.plaintext)
                .await
                .map_err(|e| headscale_db::DbError::General(e.to_string()))?
        );
        assert_eq!(
            api_keys::get_postgres_by_id_on_connection(&mut schema.conn, created.row.id)
                .await?
                .prefix,
            created.row.prefix
        );
        assert_eq!(
            api_keys::get_postgres_by_prefix_on_connection(
                &mut schema.conn,
                &created.row.display_prefix(),
            )
            .await?
            .id,
            created.row.id
        );
        let second = api_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            api_keys::CreateParams { expiration: None },
        )
        .await?;
        assert_eq!(
            api_keys::list_postgres_on_connection(&mut schema.conn)
                .await?
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![created.row.id, second.row.id]
        );

        api_keys::expire_postgres_by_prefix_on_connection(
            &mut schema.conn,
            &created.row.display_prefix(),
        )
        .await?;
        let expired =
            api_keys::get_postgres_by_id_on_connection(&mut schema.conn, created.row.id).await?;
        assert!(expired.expiration.is_some());
        assert!(
            !api_keys::validate_postgres_on_connection(&mut schema.conn, &created.plaintext)
                .await
                .map_err(|e| headscale_db::DbError::General(e.to_string()))?
        );

        api_keys::destroy_postgres_by_prefix_on_connection(
            &mut schema.conn,
            &created.row.display_prefix(),
        )
        .await?;
        api_keys::destroy_postgres_by_prefix_on_connection(
            &mut schema.conn,
            &second.row.display_prefix(),
        )
        .await?;
        assert!(
            api_keys::list_postgres_on_connection(&mut schema.conn)
                .await?
                .is_empty()
        );

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_api_key_validation_accepts_legacy_hash_rows() -> TestResult {
    let Some(mut schema) = TempSchema::open("legacy_api_keys").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let prefix = "legacy1";
        let secret = "s".repeat(api_keys::LEGACY_API_KEY_SECRET_LEN);
        let hash = bcrypt::hash(&secret, api_keys::BCRYPT_COST_TEST)
            .map_err(|e| headscale_db::DbError::General(e.to_string()))?;
        let now = temporary_timestamp();
        sqlx::query(
            "
            INSERT INTO api_keys (prefix, hash, expiration, last_seen, created_at)
            VALUES ($1, $2, to_timestamp($3), to_timestamp($4), to_timestamp($5))
            ",
        )
        .bind(prefix)
        .bind(hash.as_bytes())
        .bind(now + 3600)
        .bind(now - 60)
        .bind(now)
        .execute(&mut schema.conn)
        .await?;

        assert!(
            api_keys::validate_postgres_on_connection(
                &mut schema.conn,
                &format!("{prefix}.{secret}")
            )
            .await
            .map_err(|e| headscale_db::DbError::General(e.to_string()))?
        );
        let row = api_keys::get_postgres_by_prefix_on_connection(&mut schema.conn, prefix).await?;
        assert_eq!(row.secret_hash, hash);
        assert_eq!(row.expiration, Some(now + 3600));
        assert_eq!(row.last_seen, Some(now - 60));
        assert_eq!(row.created_at, now);

        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

struct TempSchema {
    pool: PgPool,
    conn: PgConnection,
    quoted_name: String,
}

impl TempSchema {
    async fn open(test_name: &str) -> Result<Option<Self>, headscale_db::DbError> {
        let Ok(url) = std::env::var(POSTGRES_TEST_URL_ENV) else {
            eprintln!(
                "skipping Postgres foundation smoke {test_name}: {POSTGRES_TEST_URL_ENV} is not set"
            );
            return Ok(None);
        };

        let pool = open_postgres_pool(&url).await?;
        let mut conn = pool.acquire().await?.detach();
        let schema = temporary_schema_name(test_name);
        let quoted_name = quote_pg_identifier(&schema);

        sqlx::query(&format!("CREATE SCHEMA {quoted_name}"))
            .execute(&mut conn)
            .await?;
        sqlx::query(&format!("SET search_path TO {quoted_name}"))
            .execute(&mut conn)
            .await?;

        Ok(Some(Self {
            pool,
            conn,
            quoted_name,
        }))
    }

    async fn cleanup(self) -> Result<(), headscale_db::DbError> {
        let mut conn = self.conn;
        sqlx::query(&format!(
            "DROP SCHEMA IF EXISTS {} CASCADE",
            self.quoted_name
        ))
        .execute(&mut conn)
        .await?;
        self.pool.close().await;
        Ok(())
    }
}

fn temporary_schema_name(test_name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after UNIX epoch")
        .as_nanos();
    format!(
        "headscale_rs_pg_foundation_{}_{}_{}",
        std::process::id(),
        test_name,
        nanos
    )
}

fn temporary_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after UNIX epoch")
        .as_secs() as i64
}

async fn postgres_table_exists(
    conn: &mut PgConnection,
    table: &str,
) -> Result<bool, headscale_db::DbError> {
    Ok(sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut *conn)
        .await?)
}

fn quote_pg_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}
