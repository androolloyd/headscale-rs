#![cfg(all(feature = "postgres-sqlx", feature = "go-pool-compat"))]

//! The production server opens Postgres through the database/sql-compatible
//! pool (`open_postgres_pool_with_options`), not the foundation-tool pool the
//! other live-Postgres tests use. This runs the startup sequence the server
//! performs (open, migrate, ping) over that pool in a throwaway database.

use headscale_db::{
    GoPostgresPoolOptions, check_postgres_health, migrate_postgres_foundation, open_postgres_pool,
    open_postgres_pool_with_options,
};
use std::time::{SystemTime, UNIX_EPOCH};

const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn url_for_database(url: &str, database: &str) -> String {
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(b, q)| (b, Some(q)));
    let (prefix, _) = base.rsplit_once('/').expect("test URL has a database path");
    match query {
        Some(query) => format!("{prefix}/{database}?{query}"),
        None => format!("{prefix}/{database}"),
    }
}

#[tokio::test]
async fn go_compatible_pool_opens_migrates_and_pings() -> TestResult {
    let Ok(url) = std::env::var(POSTGRES_TEST_URL_ENV) else {
        eprintln!("skipping Go pool Postgres test: {POSTGRES_TEST_URL_ENV} is not set");
        return Ok(());
    };
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let database = format!("hs_go_pool_{}_{nonce}", std::process::id());
    let admin = open_postgres_pool(&url).await?;
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;

    let result = async {
        let pool = open_postgres_pool_with_options(
            &url_for_database(&url, &database),
            GoPostgresPoolOptions::default(),
        )
        .await?;
        migrate_postgres_foundation(&pool).await?;
        check_postgres_health(&pool).await?;
        pool.close().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    sqlx::query(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
        .execute(&admin)
        .await?;
    admin.close().await;
    result
}
