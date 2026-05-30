#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    DbError, migrate_postgres_foundation_on_connection, open_postgres_pool,
    preauth_keys::{self, CreateParams, TOKEN_PREFIX, UseError},
    users,
};
use sqlx::{PgConnection, PgPool};
use std::time::{SystemTime, UNIX_EPOCH};

const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn postgres_preauth_key_primitives_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("preauth_contract").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let alice = seed_user(&mut schema.conn, "alice").await?;
        let bob = seed_user(&mut schema.conn, "bob").await?;

        let created = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: "alice".into(),
                reusable: false,
                ephemeral: true,
                tags: vec!["tag:server".into()],
                expiration: None,
            },
        )
        .await?;

        assert!(created.plaintext.starts_with(TOKEN_PREFIX));
        assert_eq!(created.row.user_id, alice.id.to_string());
        assert!(created.row.key.is_none());
        assert!(created.row.key_hash.starts_with("$2"));
        assert!(!created.row.reusable);
        assert!(created.row.ephemeral);
        assert_eq!(created.row.tag_list(), vec!["tag:server".to_string()]);
        assert!(created.row.created_at > 0);
        assert!(created.row.used_at.is_none());
        assert_eq!(
            created.row.display_key(),
            format!(
                "{TOKEN_PREFIX}{}-***",
                created.row.prefix.as_deref().expect("modern prefix")
            )
        );

        assert_eq!(
            preauth_keys::get_postgres_by_id_on_connection(&mut schema.conn, created.row.id)
                .await?
                .key_hash,
            created.row.key_hash
        );
        assert_eq!(
            preauth_keys::get_postgres_by_token_on_connection(&mut schema.conn, &created.plaintext)
                .await?
                .id,
            created.row.id
        );

        let wrong_secret = format!(
            "{TOKEN_PREFIX}{}-{}",
            created.row.prefix.as_deref().expect("modern prefix"),
            "0".repeat(64)
        );
        assert!(matches!(
            preauth_keys::get_postgres_by_token_on_connection(&mut schema.conn, &wrong_secret)
                .await
                .unwrap_err(),
            DbError::NotFound(_)
        ));

        let alice_keys =
            preauth_keys::list_postgres_by_user_on_connection(&mut schema.conn, "alice").await?;
        assert_eq!(alice_keys.len(), 1);
        assert_eq!(alice_keys[0].id, created.row.id);
        assert!(
            preauth_keys::list_postgres_by_user_on_connection(&mut schema.conn, "missing")
                .await?
                .is_empty()
        );

        let userless = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: String::new(),
                reusable: false,
                ephemeral: false,
                tags: vec!["tag:gateway".into()],
                expiration: None,
            },
        )
        .await?;
        assert_eq!(userless.row.user_id, "");
        assert_eq!(
            preauth_keys::list_all_postgres_on_connection(&mut schema.conn)
                .await?
                .len(),
            2
        );

        let used =
            preauth_keys::try_use_postgres_on_connection(&mut schema.conn, &created.plaintext)
                .await
                .map_err(|e| DbError::General(e.to_string()))?;
        assert!(used.used_at.is_some());
        assert_eq!(
            preauth_keys::try_use_postgres_on_connection(&mut schema.conn, &created.plaintext)
                .await
                .unwrap_err(),
            UseError::AlreadyUsed
        );

        let reusable = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: bob.id.to_string(),
                reusable: true,
                ephemeral: false,
                tags: Vec::new(),
                expiration: Some(temporary_timestamp() + 3600),
            },
        )
        .await?;
        for _ in 0..2 {
            let row =
                preauth_keys::try_use_postgres_on_connection(&mut schema.conn, &reusable.plaintext)
                    .await
                    .map_err(|e| DbError::General(e.to_string()))?;
            assert!(row.used_at.is_none());
        }
        assert!(
            !preauth_keys::get_postgres_by_id_on_connection(&mut schema.conn, reusable.row.id)
                .await?
                .is_used()
        );

        let expiring = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: "alice".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: Some(temporary_timestamp() + 3600),
            },
        )
        .await?;
        preauth_keys::expire_postgres_on_connection(&mut schema.conn, expiring.row.id).await?;
        assert_eq!(
            preauth_keys::try_use_postgres_on_connection(&mut schema.conn, &expiring.plaintext)
                .await
                .unwrap_err(),
            UseError::Expired
        );

        preauth_keys::destroy_postgres_on_connection(&mut schema.conn, userless.row.id).await?;
        assert!(matches!(
            preauth_keys::get_postgres_by_id_on_connection(&mut schema.conn, userless.row.id)
                .await
                .unwrap_err(),
            DbError::NotFound(_)
        ));

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_preauth_keys_accept_headscale_go_legacy_plaintext_rows() -> TestResult {
    let Some(mut schema) = TempSchema::open("preauth_legacy").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;
        let alice = seed_user(&mut schema.conn, "alice").await?;

        let key = "legacy-preauth-key";
        let created_at = temporary_timestamp();
        sqlx::query(
            "
            INSERT INTO pre_auth_keys
                (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
            VALUES ($1, NULL, NULL, $2, false, false, false, $3, NULL, to_timestamp(($4::BIGINT)::DOUBLE PRECISION))
            ",
        )
        .bind(key)
        .bind(alice.id)
        .bind(r#"["tag:legacy"]"#)
        .bind(created_at)
        .execute(&mut schema.conn)
        .await?;

        let row = preauth_keys::get_postgres_by_token_on_connection(&mut schema.conn, key).await?;
        assert_eq!(row.key.as_deref(), Some(key));
        assert_eq!(row.user_id, alice.id.to_string());
        assert_eq!(row.tag_list(), vec!["tag:legacy".to_string()]);
        assert_eq!(row.created_at, created_at);
        assert!(row.used_at.is_none());

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_preauth_key_create_rejects_missing_users_like_sqlite() -> TestResult {
    let Some(mut schema) = TempSchema::open("preauth_missing_user").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let err = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: "missing".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DbError::Constraint(_)));

        let err = preauth_keys::create_postgres_for_test_on_connection(
            &mut schema.conn,
            CreateParams {
                user_id: String::new(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DbError::General(_)));

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

async fn seed_user(conn: &mut PgConnection, name: &str) -> Result<users::UserRow, DbError> {
    users::create_postgres_on_connection(
        conn,
        users::CreateParams {
            name: name.into(),
            display_name: name.into(),
            email: format!("{name}@example.com"),
            provider_identifier: None,
            provider: "cli".into(),
            profile_pic_url: String::new(),
        },
    )
    .await
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
                "skipping Postgres preauth-key smoke {test_name}: {POSTGRES_TEST_URL_ENV} is not set"
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
        "headscale_rs_pg_preauth_{}_{}_{}",
        std::process::id(),
        test_name,
        nanos
    )
}

fn quote_pg_identifier(identifier: &str) -> String {
    format!(r#""{}""#, identifier.replace('"', r#""""#))
}

fn temporary_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after UNIX epoch")
        .as_secs() as i64
}
