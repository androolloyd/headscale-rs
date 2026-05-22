use headscale_db::{
    Database, headscale_nodes,
    preauth_keys::{self, CreateParams as PreauthCreateParams},
    users::{self, CreateParams as UserCreateParams},
};

const LEGACY_ROUTES_MIGRATION: &str =
    include_str!("../migrations/20260522000010_migrate_legacy_routes.sql");

async fn user_id(db: &Database) -> i64 {
    users::create(
        db.pool(),
        UserCreateParams {
            name: "alice".into(),
            display_name: "Alice".into(),
            email: "alice@example.com".into(),
            provider_identifier: None,
            provider: "cli".into(),
            profile_pic_url: String::new(),
        },
    )
    .await
    .expect("create user")
    .id
}

async fn preauth_key_id(db: &Database, user_id: i64) -> i64 {
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
    .expect("create preauth key")
    .row
    .id
}

async fn node_with_route(
    db: &Database,
    user_id: i64,
    auth_key_id: i64,
) -> headscale_nodes::HeadscaleNodeRow {
    headscale_nodes::create(
        db.pool(),
        headscale_nodes::CreateParams {
            machine_key: "mkey:legacy".into(),
            node_key: "nodekey:legacy".into(),
            disco_key: "discokey:legacy".into(),
            endpoints: Vec::new(),
            host_info: serde_json::json!({
                "Hostname": "alice-laptop",
                "RoutableIPs": ["10.1.0.0/24", "10.2.0.0/24"],
            }),
            ipv4: Some("100.64.0.1".into()),
            ipv6: Some("fd7a:115c:a1e0::1".into()),
            hostname: "alice-laptop".into(),
            given_name: "alice-laptop".into(),
            user_id: Some(user_id),
            register_method: headscale_nodes::REGISTER_METHOD_AUTH_KEY.into(),
            tags: Vec::new(),
            auth_key_id: Some(auth_key_id),
            expiry: None,
            last_seen: None,
            approved_routes: vec!["10.0.0.0/24".into()],
        },
    )
    .await
    .expect("create node")
}

#[tokio::test]
async fn documents_preauth_user_id_fk_on_delete_set_null_schema_gap() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");

    let preauth_user_fks: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT "from", "table", "to", on_delete
        FROM pragma_foreign_key_list('pre_auth_keys')
        "#,
    )
    .fetch_all(db.pool())
    .await
    .expect("query pre_auth_keys foreign keys");
    assert!(
        !preauth_user_fks
            .iter()
            .any(|(from, table, to, on_delete)| from == "user_id"
                && table == "users"
                && to == "id"
                && on_delete.eq_ignore_ascii_case("SET NULL")),
        "headscale-go v0.28.0 has pre_auth_keys.user_id -> users(id) ON DELETE SET NULL; \
         this is still a known gap while the DB crate accepts string user labels"
    );

    sqlx::query(
        "
        INSERT INTO pre_auth_keys
            (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
        VALUES
            ('legacy-string-user-key', NULL, NULL, 'legacy-string-user', false, false, false, '[]', NULL, datetime('now'))
        ",
    )
    .execute(db.pool())
    .await
    .expect("current schema accepts string user labels");
    let string_user_type: String =
        sqlx::query_scalar("SELECT typeof(user_id) FROM pre_auth_keys WHERE key = ?")
            .bind("legacy-string-user-key")
            .fetch_one(db.pool())
            .await
            .expect("query string user storage type");
    assert_eq!(
        string_user_type, "text",
        "a strict upstream FK migration would reject this current compatibility path"
    );

    let user_id = user_id(&db).await;
    let auth_key_id = preauth_key_id(&db, user_id).await;
    users::destroy(db.pool(), user_id)
        .await
        .expect("delete owning user");

    let stale_user_id: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM pre_auth_keys WHERE id = ?")
            .bind(auth_key_id)
            .fetch_one(db.pool())
            .await
            .expect("query preauth key after user delete");
    assert_eq!(
        stale_user_id,
        Some(user_id),
        "upstream would keep the preauth key row but SET NULL on user deletion"
    );
}

#[tokio::test]
async fn migrates_legacy_routes_table_enabled_rows_to_nodes_approved_routes_and_drops_routes() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");

    let user_id = user_id(&db).await;
    let auth_key_id = preauth_key_id(&db, user_id).await;
    let node = node_with_route(&db, user_id, auth_key_id).await;

    sqlx::raw_sql(
        "
        CREATE TABLE routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME,
            updated_at DATETIME,
            deleted_at DATETIME,
            node_id INTEGER NOT NULL,
            prefix TEXT,
            advertised BOOLEAN,
            enabled BOOLEAN,
            is_primary BOOLEAN
        );
        INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary)
            VALUES (1, '10.1.0.0/24', 1, 1, 0);
        INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary)
            VALUES (1, '0.0.0.0/0', 1, 1, 1);
        INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary)
            VALUES (1, '10.2.0.0/24', 1, 0, 0);
        INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary, deleted_at)
            VALUES (1, '10.3.0.0/24', 1, 1, 0, '2026-05-22 00:00:00');
        INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary)
            VALUES (999, '10.99.0.0/24', 1, 1, 0);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed legacy routes");

    sqlx::raw_sql(LEGACY_ROUTES_MIGRATION)
        .execute(db.pool())
        .await
        .expect("run legacy routes migration");

    let migrated = headscale_nodes::get_by_id(db.pool(), node.id)
        .await
        .expect("reload node");
    assert_eq!(
        migrated.approved_route_list(),
        vec!["0.0.0.0/0", "10.0.0.0/24", "10.1.0.0/24", "::/0"]
    );
    assert_eq!(
        migrated.host_info_value()["RoutableIPs"],
        serde_json::json!(["10.1.0.0/24", "10.2.0.0/24"])
    );

    let routes_table: Option<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'routes'",
    )
    .fetch_optional(db.pool())
    .await
    .expect("query sqlite schema");
    assert!(routes_table.is_none());
}
