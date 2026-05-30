#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    HEADSCALE_GO_CURRENT_VERSION, check_postgres_health_on_connection,
    migrate_postgres_foundation_on_connection, open_postgres_pool, policies,
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
