#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    HEADSCALE_GO_CURRENT_VERSION, migrate_postgres_foundation_on_connection, open_postgres_pool,
};
use std::time::{SystemTime, UNIX_EPOCH};

const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

#[tokio::test]
async fn postgres_foundation_creates_and_stamps_database_versions() {
    let Ok(url) = std::env::var(POSTGRES_TEST_URL_ENV) else {
        eprintln!("skipping Postgres foundation smoke: {POSTGRES_TEST_URL_ENV} is not set");
        return;
    };

    let pool = open_postgres_pool(&url)
        .await
        .expect("open Postgres test URL");
    let schema = temporary_schema_name();
    let quoted_schema = quote_pg_identifier(&schema);
    let mut conn = pool.acquire().await.expect("acquire Postgres connection");

    sqlx::query(&format!("CREATE SCHEMA {quoted_schema}"))
        .execute(&mut *conn)
        .await
        .expect("create temporary Postgres test schema");

    let result = async {
        sqlx::query(&format!("SET search_path TO {quoted_schema}"))
            .execute(&mut *conn)
            .await?;
        migrate_postgres_foundation_on_connection(&mut conn).await?;

        let row: (i64, String, bool) = sqlx::query_as(
            "
            SELECT id, version, updated_at IS NOT NULL
            FROM database_versions
            ",
        )
        .fetch_one(&mut *conn)
        .await?;

        assert_eq!(row, (1, HEADSCALE_GO_CURRENT_VERSION.to_string(), true));
        Ok::<(), headscale_db::DbError>(())
    }
    .await;

    sqlx::query(&format!("DROP SCHEMA IF EXISTS {quoted_schema} CASCADE"))
        .execute(&mut *conn)
        .await
        .expect("drop temporary Postgres test schema");
    pool.close().await;

    result.expect("run Postgres foundation migration smoke");
}

fn temporary_schema_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after UNIX epoch")
        .as_nanos();
    format!(
        "headscale_rs_pg_foundation_{}_{}",
        std::process::id(),
        nanos
    )
}

fn quote_pg_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}
