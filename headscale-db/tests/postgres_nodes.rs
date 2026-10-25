#![cfg(feature = "postgres-sqlx")]

use headscale_db::{
    DbError, headscale_nodes, migrate_postgres_foundation_on_connection, open_postgres_pool,
    preauth_keys, users,
};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use std::time::{SystemTime, UNIX_EPOCH};

const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn postgres_node_primitives_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("nodes_contract").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let alice = seed_user(&mut schema.conn, "alice").await?;
        let auth_key_id = seed_auth_key(&mut schema.conn, alice.id).await?;
        let node = headscale_nodes::create_postgres_on_connection(
            &mut schema.conn,
            node_params(alice.id, auth_key_id),
        )
        .await?;

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
        assert_eq!(node.endpoint_list(), vec!["203.0.113.5:41641"]);
        assert_eq!(node.host_info_value()["OS"], "linux");
        assert_eq!(node.ipv4.as_deref(), Some("100.64.0.1"));
        assert_eq!(node.ipv6.as_deref(), Some("fd7a:115c:a1e0::1"));
        assert_eq!(node.user_id, Some(alice.id));
        assert_eq!(node.auth_key_id, Some(auth_key_id));
        assert_eq!(node.approved_route_list(), vec!["10.0.0.0/24"]);
        assert_eq!(node.created_at, node.updated_at);
        assert!(node.deleted_at.is_none());

        assert_eq!(
            headscale_nodes::get_postgres_by_id_on_connection(&mut schema.conn, node.id)
                .await?
                .node_key,
            node.node_key
        );
        assert_eq!(
            headscale_nodes::get_postgres_by_node_key_on_connection(
                &mut schema.conn,
                "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a",
            )
            .await?
            .id,
            node.id
        );
        assert_eq!(
            headscale_nodes::get_postgres_by_machine_key_and_user_on_connection(
                &mut schema.conn,
                "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a",
                alice.id,
            )
            .await?
            .id,
            node.id
        );
        assert_eq!(
            headscale_nodes::list_postgres_on_connection(&mut schema.conn)
                .await?
                .len(),
            1
        );
        assert_eq!(
            headscale_nodes::list_postgres_by_user_on_connection(&mut schema.conn, alice.id)
                .await?
                .len(),
            1
        );

        let routes = headscale_nodes::set_postgres_approved_routes_on_connection(
            &mut schema.conn,
            node.id,
            vec!["::/0".into()],
        )
        .await?
        .approved_route_list();
        assert_eq!(routes, vec!["0.0.0.0/0", "::/0"]);

        let routed = headscale_nodes::set_postgres_host_info_routable_ips_on_connection(
            &mut schema.conn,
            node.id,
            vec!["10.2.0.0/16".into()],
        )
        .await?;
        assert_eq!(
            routed.host_info_value()["RoutableIPs"],
            json!(["10.2.0.0/16"])
        );
        assert_eq!(routed.approved_route_list(), routes);

        let tagged = headscale_nodes::set_postgres_tags_on_connection(
            &mut schema.conn,
            node.id,
            vec!["tag:prod".into(), "tag:dev".into(), "tag:prod".into()],
        )
        .await?;
        assert_eq!(tagged.tag_list(), vec!["tag:dev", "tag:prod"]);
        assert!(tagged.user_id.is_none());
        assert!(
            headscale_nodes::list_postgres_by_user_on_connection(&mut schema.conn, alice.id)
                .await?
                .is_empty()
        );
        let untagged =
            headscale_nodes::set_postgres_tags_on_connection(&mut schema.conn, node.id, Vec::new())
                .await?;
        assert!(untagged.tag_list().is_empty());
        assert_eq!(untagged.tags, "[]");
        assert!(untagged.user_id.is_none());

        let mut replacement = node_params(alice.id, auth_key_id);
        replacement.machine_key =
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        replacement.node_key =
            "nodekey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        replacement.disco_key =
            "discokey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c".into();
        replacement.endpoints = vec!["198.51.100.10:41641".into()];
        replacement.given_name = "alice-new".into();
        replacement.tags = Vec::new();
        replacement.approved_routes = vec!["0.0.0.0/0".into()];
        let updated = headscale_nodes::update_postgres_from_auth_path_on_connection(
            &mut schema.conn,
            node.id,
            replacement,
        )
        .await?;
        assert_eq!(
            updated.machine_key,
            "mkey:d6301922bddad7771082a5371804c99eabc897ad8dc48dc0f9032018ee2fda5c"
        );
        assert_eq!(updated.user_id, Some(alice.id));
        assert!(updated.tag_list().is_empty());
        // Go expands exit routes only in the gRPC SetApprovedRoutes handler;
        // an auth-path update stores the routes it is given.
        assert_eq!(updated.approved_route_list(), vec!["0.0.0.0/0"]);

        let expiry = temporary_timestamp() + 3600;
        assert_eq!(
            headscale_nodes::set_postgres_expiry_on_connection(
                &mut schema.conn,
                node.id,
                Some(expiry),
            )
            .await?
            .expiry,
            Some(expiry)
        );
        let last_seen = temporary_timestamp();
        assert_eq!(
            headscale_nodes::set_postgres_last_seen_on_connection(
                &mut schema.conn,
                node.id,
                Some(last_seen),
            )
            .await?
            .last_seen,
            Some(last_seen)
        );
        let precise_disconnect = chrono::DateTime::from_timestamp(last_seen + 1, 123_456_000)
            .expect("precise disconnect timestamp");
        headscale_nodes::persist_postgres_last_seen_at_on_connection(
            &mut schema.conn,
            node.id,
            &precise_disconnect,
        )
        .await?;
        let expected_disconnect =
            precise_disconnect.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        assert_eq!(
            headscale_nodes::get_postgres_by_id_on_connection(&mut schema.conn, node.id)
                .await?
                .last_seen_text
                .as_deref(),
            Some(expected_disconnect.as_str())
        );
        let addressed = headscale_nodes::set_postgres_ip_addresses_on_connection(
            &mut schema.conn,
            node.id,
            Some("100.64.0.2".into()),
            None,
        )
        .await?;
        assert_eq!(addressed.ipv4.as_deref(), Some("100.64.0.2"));
        assert!(addressed.ipv6.is_none());

        let renamed =
            headscale_nodes::rename_postgres_on_connection(&mut schema.conn, node.id, "renamed")
                .await?;
        assert_eq!(renamed.given_name, "renamed");

        let logged_out =
            headscale_nodes::logout_postgres_on_connection(&mut schema.conn, node.id).await?;
        assert!(logged_out.expiry.is_some());

        headscale_nodes::destroy_postgres_on_connection(&mut schema.conn, node.id).await?;
        assert!(
            headscale_nodes::list_postgres_on_connection(&mut schema.conn)
                .await?
                .is_empty()
        );

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_node_unique_constraints_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("nodes_unique").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let alice = seed_user(&mut schema.conn, "alice").await?;
        let auth_key_id = seed_auth_key(&mut schema.conn, alice.id).await?;
        let node = headscale_nodes::create_postgres_on_connection(
            &mut schema.conn,
            node_params(alice.id, auth_key_id),
        )
        .await?;

        let mut duplicate_name = node_params(alice.id, auth_key_id);
        duplicate_name.machine_key =
            "mkey:55763a9e6ec62fc5cacdcea3c58b095d95555eb1283f31cd85d8ca911a229154".into();
        duplicate_name.node_key =
            "nodekey:55763a9e6ec62fc5cacdcea3c58b095d95555eb1283f31cd85d8ca911a229154".into();
        duplicate_name.disco_key =
            "discokey:55763a9e6ec62fc5cacdcea3c58b095d95555eb1283f31cd85d8ca911a229154".into();
        duplicate_name.ipv4 = Some("100.64.0.10".into());
        duplicate_name.ipv6 = Some("fd7a:115c:a1e0::10".into());
        assert!(matches!(
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, duplicate_name)
                .await
                .unwrap_err(),
            DbError::General(_)
        ));

        let mut duplicate_ipv4 = node_params(alice.id, auth_key_id);
        duplicate_ipv4.machine_key =
            "mkey:5de5749c50499e066e2cfefa843e332554c43c7a11df3c8dc58f98295ae220b3".into();
        duplicate_ipv4.node_key =
            "nodekey:5de5749c50499e066e2cfefa843e332554c43c7a11df3c8dc58f98295ae220b3".into();
        duplicate_ipv4.disco_key =
            "discokey:5de5749c50499e066e2cfefa843e332554c43c7a11df3c8dc58f98295ae220b3".into();
        duplicate_ipv4.given_name = "node-ipv4".into();
        duplicate_ipv4.ipv6 = Some("fd7a:115c:a1e0::11".into());
        assert!(matches!(
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, duplicate_ipv4)
                .await
                .unwrap_err(),
            DbError::General(_)
        ));

        let mut duplicate_node_key = node_params(alice.id, auth_key_id);
        duplicate_node_key.machine_key =
            "mkey:f140da8b6291401b16c67cc17f0734c8750338d12edb60ed95368d0ff1d2dc8b".into();
        duplicate_node_key.disco_key =
            "discokey:f140da8b6291401b16c67cc17f0734c8750338d12edb60ed95368d0ff1d2dc8b".into();
        duplicate_node_key.hostname = "node-key".into();
        duplicate_node_key.given_name = "node-key".into();
        duplicate_node_key.ipv4 = Some("100.64.0.12".into());
        duplicate_node_key.ipv6 = Some("fd7a:115c:a1e0::12".into());
        let duplicate_node_key =
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, duplicate_node_key)
                .await?;
        assert_ne!(duplicate_node_key.id, node.id);
        assert_eq!(duplicate_node_key.node_key, node.node_key);

        let mut second_params = node_params(alice.id, auth_key_id);
        second_params.machine_key =
            "mkey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        second_params.node_key =
            "nodekey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        second_params.disco_key =
            "discokey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        second_params.hostname = "second".into();
        second_params.given_name = "second".into();
        second_params.ipv4 = Some("100.64.0.13".into());
        second_params.ipv6 = Some("fd7a:115c:a1e0::13".into());
        let second =
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, second_params).await?;

        let mut duplicate_update = node_params(alice.id, auth_key_id);
        duplicate_update.machine_key =
            "mkey:42f1e5b3cbfa1adfd8a8fadea7a6b1e1b0319c5b2ae2d305285d24efb478d214".into();
        duplicate_update.disco_key =
            "discokey:2135ab5c0db910735396983ff2c47c74d043094e5938d2868847607bde512d61".into();
        duplicate_update.hostname = "duplicate-update".into();
        duplicate_update.given_name = "duplicate-update".into();
        duplicate_update.ipv4 = Some("100.64.0.14".into());
        duplicate_update.ipv6 = Some("fd7a:115c:a1e0::14".into());
        let updated = headscale_nodes::update_postgres_from_auth_path_on_connection(
            &mut schema.conn,
            second.id,
            duplicate_update,
        )
        .await?;
        assert_eq!(updated.node_key, node.node_key);
        assert_eq!(
            headscale_nodes::get_postgres_by_node_key_on_connection(
                &mut schema.conn,
                &node.node_key,
            )
            .await?
            .id,
            node.id
        );

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_new_registration_bumps_colliding_given_name_like_go_nodestore() -> TestResult {
    let Some(mut schema) = TempSchema::open("nodes_new_registration_given_name").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let mut names = Vec::new();
        for (n, given_name) in [(1_u8, "laptop"), (2, "laptop"), (3, "laptop"), (4, "")] {
            let row = headscale_nodes::create_postgres_new_registration_on_connection(
                &mut schema.conn,
                headscale_nodes::NewNodeRegistration {
                    machine_key: format!("mkey:{n:064x}"),
                    node_key: format!("nodekey:{n:064x}"),
                    disco_key: format!("discokey:{n:064x}"),
                    endpoints: None,
                    host_info: None,
                    ipv4: Some(format!("100.64.0.{n}")),
                    ipv6: None,
                    hostname: "Laptop".into(),
                    given_name: given_name.into(),
                    user_id: None,
                    register_method: headscale_nodes::REGISTER_METHOD_AUTH_KEY.into(),
                    tags: None,
                    auth_key_id: None,
                    expiry: None,
                    last_seen: None,
                    approved_routes: None,
                },
            )
            .await?;
            names.push(row.given_name);
        }
        assert_eq!(names, ["laptop", "laptop-1", "laptop-2", "laptop-3"]);

        let stored: Vec<String> = sqlx::query_scalar("SELECT given_name FROM nodes ORDER BY id")
            .fetch_all(&mut schema.conn)
            .await?;
        assert_eq!(stored, names);
        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_nodes_given_name_matches_headscale_go_length() -> TestResult {
    let Some(mut schema) = TempSchema::open("nodes_given_name_length").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let column: (String, Option<i32>) = sqlx::query_as(
            "
            SELECT data_type, character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'nodes'
              AND column_name = 'given_name'
            ",
        )
        .fetch_one(&mut schema.conn)
        .await?;
        assert_eq!(column, ("character varying".to_string(), Some(63)));

        let max_length_name = "a".repeat(63);
        sqlx::query("INSERT INTO nodes (given_name) VALUES ($1)")
            .bind(&max_length_name)
            .execute(&mut schema.conn)
            .await?;

        let too_long_name = "b".repeat(64);
        let err = sqlx::query("INSERT INTO nodes (given_name) VALUES ($1)")
            .bind(&too_long_name)
            .execute(&mut schema.conn)
            .await
            .expect_err("Postgres should reject nodes.given_name longer than 63 characters");
        assert!(
            err.to_string()
                .contains("value too long for type character varying(63)"),
            "unexpected error for long given_name: {err}"
        );

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

#[tokio::test]
async fn postgres_node_list_helpers_match_sqlite_contract() -> TestResult {
    let Some(mut schema) = TempSchema::open("nodes_list_helpers").await? else {
        return Ok(());
    };

    let result = async {
        migrate_postgres_foundation_on_connection(&mut schema.conn).await?;

        let alice = seed_user(&mut schema.conn, "alice").await?;
        let auth_key_id = seed_auth_key(&mut schema.conn, alice.id).await?;
        let first = headscale_nodes::create_postgres_on_connection(
            &mut schema.conn,
            node_params(alice.id, auth_key_id),
        )
        .await?;

        let mut second_params = node_params(alice.id, auth_key_id);
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
        let second =
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, second_params).await?;

        let ephemeral_key_id =
            seed_auth_key_with_ephemeral(&mut schema.conn, alice.id, true).await?;
        let mut ephemeral_params = node_params(alice.id, ephemeral_key_id);
        ephemeral_params.machine_key =
            "mkey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
        ephemeral_params.node_key =
            "nodekey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
        ephemeral_params.disco_key =
            "discokey:c173a3b72118fc024557f8319e896b879d9a011f60d53c9be855382f917a0bc0".into();
        ephemeral_params.hostname = "ephemeral".into();
        ephemeral_params.given_name = "ephemeral".into();
        ephemeral_params.ipv4 = Some("100.64.0.3".into());
        ephemeral_params.ipv6 = Some("fd7a:115c:a1e0::3".into());
        let ephemeral =
            headscale_nodes::create_postgres_on_connection(&mut schema.conn, ephemeral_params)
                .await?;

        let all =
            headscale_nodes::list_postgres_by_ids_on_connection(&mut schema.conn, &[]).await?;
        assert_eq!(
            all.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![first.id, second.id, ephemeral.id]
        );

        assert!(
            headscale_nodes::list_postgres_by_ids_on_connection(&mut schema.conn, &[999])
                .await?
                .is_empty()
        );
        let partial = headscale_nodes::list_postgres_by_ids_on_connection(
            &mut schema.conn,
            &[second.id, 999],
        )
        .await?;
        assert_eq!(
            partial.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![second.id]
        );

        let peers =
            headscale_nodes::list_postgres_peers_on_connection(&mut schema.conn, first.id, &[])
                .await?;
        assert_eq!(
            peers.iter().map(|node| node.id).collect::<Vec<_>>(),
            vec![second.id, ephemeral.id]
        );
        let filtered_peers = headscale_nodes::list_postgres_peers_on_connection(
            &mut schema.conn,
            first.id,
            &[first.id, second.id, 999],
        )
        .await?;
        assert_eq!(
            filtered_peers
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            vec![second.id]
        );

        assert_eq!(
            headscale_nodes::get_postgres_by_user_hostname_on_connection(
                &mut schema.conn,
                alice.id,
                "alice-phone",
            )
            .await?
            .id,
            second.id
        );
        assert!(matches!(
            headscale_nodes::get_postgres_by_user_hostname_on_connection(
                &mut schema.conn,
                alice.id,
                "missing",
            )
            .await,
            Err(DbError::NotFound(_))
        ));

        let ephemeral_nodes =
            headscale_nodes::list_postgres_ephemeral_on_connection(&mut schema.conn).await?;
        assert_eq!(
            ephemeral_nodes
                .iter()
                .map(|node| (node.id, node.auth_key_id))
                .collect::<Vec<_>>(),
            vec![(ephemeral.id, Some(ephemeral_key_id))]
        );
        assert!(
            preauth_keys::is_postgres_ephemeral_by_id_on_connection(
                &mut schema.conn,
                ephemeral_key_id,
            )
            .await?
        );

        Ok::<(), DbError>(())
    }
    .await;

    schema.cleanup().await?;
    result?;
    Ok(())
}

fn node_params(user_id: i64, auth_key_id: i64) -> headscale_nodes::CreateParams {
    headscale_nodes::CreateParams {
        machine_key: "mkey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a".into(),
        node_key: "nodekey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a".into(),
        disco_key: "discokey:072d75b5af4db84097b6701ff1b5368aa2717916b388a8009306f8690e16f64a"
            .into(),
        endpoints: vec!["203.0.113.5:41641".into()],
        host_info: json!({
            "OS": "linux",
            "RoutableIPs": ["10.0.0.0/24"],
        }),
        ipv4: Some("100.64.0.1".into()),
        ipv6: Some("fd7a:115c:a1e0::1".into()),
        hostname: "Alice Laptop".into(),
        given_name: "alice-laptop".into(),
        user_id: Some(user_id),
        register_method: headscale_nodes::REGISTER_METHOD_AUTH_KEY.into(),
        tags: Vec::new(),
        auth_key_id: Some(auth_key_id),
        expiry: None,
        expiry_precise: None,
        last_seen: Some(temporary_timestamp()),
        last_seen_precise: None,
        approved_routes: vec!["10.0.0.0/24".into()],
    }
}

async fn seed_user(conn: &mut PgConnection, name: &str) -> Result<users::UserRow, DbError> {
    users::create_postgres_on_connection(
        conn,
        users::CreateParams {
            name: name.into(),
            display_name: name.into(),
            email: format!("{name}@example.com"),
            provider_identifier: None,
            provider: headscale_nodes::REGISTER_METHOD_CLI.into(),
            profile_pic_url: String::new(),
        },
    )
    .await
}

async fn seed_auth_key(conn: &mut PgConnection, user_id: i64) -> Result<i64, DbError> {
    seed_auth_key_with_ephemeral(conn, user_id, false).await
}

async fn seed_auth_key_with_ephemeral(
    conn: &mut PgConnection,
    user_id: i64,
    ephemeral: bool,
) -> Result<i64, DbError> {
    Ok(preauth_keys::create_postgres_for_test_on_connection(
        conn,
        preauth_keys::CreateParams {
            user_id: user_id.to_string(),
            reusable: false,
            ephemeral,
            tags: Vec::new(),
            expiration: None,
        },
    )
    .await?
    .row
    .id)
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
                "skipping Postgres node smoke {test_name}: {POSTGRES_TEST_URL_ENV} is not set"
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
        "headscale_rs_pg_nodes_{}_{}_{}",
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
