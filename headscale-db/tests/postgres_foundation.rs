#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    HEADSCALE_GO_CURRENT_VERSION, check_postgres_health_on_connection,
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

fn quote_pg_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}
