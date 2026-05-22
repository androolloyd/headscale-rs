use headscale_db::{
    Database, DbError, HeadscaleGoImportCompatibility, headscale_nodes,
    preauth_keys::{self, CreateParams as PreauthCreateParams},
    users::{self, CreateParams as UserCreateParams},
};
use tempfile::TempDir;

const LEGACY_ROUTES_MIGRATION: &str =
    include_str!("../migrations/20260522000010_migrate_legacy_routes.sql");

const HEADSCALE_GO_V028_FIXTURE: &str = r#"
CREATE TABLE migrations(id text, PRIMARY KEY(id));
INSERT INTO migrations VALUES('202312101416');
INSERT INTO migrations VALUES('202312101430');
INSERT INTO migrations VALUES('202402151347');
INSERT INTO migrations VALUES('2024041121742');
INSERT INTO migrations VALUES('202406021630');
INSERT INTO migrations VALUES('202407191627');
INSERT INTO migrations VALUES('202408181235');
INSERT INTO migrations VALUES('202409271400');
INSERT INTO migrations VALUES('202501221827');
INSERT INTO migrations VALUES('202501311657');
INSERT INTO migrations VALUES('202502070949');
INSERT INTO migrations VALUES('202502131714');
INSERT INTO migrations VALUES('202502171819');
INSERT INTO migrations VALUES('202505091439');
INSERT INTO migrations VALUES('202505141324');
INSERT INTO migrations VALUES('202507021200');
INSERT INTO migrations VALUES('202510311551');
INSERT INTO migrations VALUES('202511011637-preauthkey-bcrypt');
INSERT INTO migrations VALUES('202511101554-drop-old-idx');
INSERT INTO migrations VALUES('202511122344-remove-newline-index');
INSERT INTO migrations VALUES('202511131445-node-forced-tags-to-tags');
INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');

CREATE TABLE users(
    id integer PRIMARY KEY AUTOINCREMENT,
    name text,
    display_name text,
    email text,
    provider_identifier text,
    provider text,
    profile_pic_url text,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime
);
CREATE UNIQUE INDEX idx_provider_identifier
    ON users(provider_identifier)
    WHERE provider_identifier IS NOT NULL;
CREATE UNIQUE INDEX idx_name_provider_identifier ON users(name, provider_identifier);
CREATE UNIQUE INDEX idx_name_no_provider_identifier
    ON users(name)
    WHERE provider_identifier IS NULL;

CREATE TABLE pre_auth_keys(
    id integer PRIMARY KEY AUTOINCREMENT,
    key text,
    prefix text,
    hash blob,
    user_id integer,
    reusable numeric,
    ephemeral numeric DEFAULT false,
    used numeric DEFAULT false,
    tags text,
    expiration datetime,
    created_at datetime,
    CONSTRAINT fk_pre_auth_keys_user
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_pre_auth_keys_prefix
    ON pre_auth_keys(prefix)
    WHERE prefix IS NOT NULL AND prefix != '';

CREATE TABLE api_keys(
    id integer PRIMARY KEY AUTOINCREMENT,
    prefix text,
    hash blob,
    expiration datetime,
    last_seen datetime,
    created_at datetime
);
CREATE UNIQUE INDEX idx_api_keys_prefix ON api_keys(prefix);

CREATE TABLE nodes(
    id integer PRIMARY KEY AUTOINCREMENT,
    machine_key text,
    node_key text,
    disco_key text,
    endpoints text,
    host_info text,
    ipv4 text,
    ipv6 text,
    hostname text,
    given_name varchar(63),
    user_id integer,
    register_method text,
    tags text,
    auth_key_id integer,
    last_seen datetime,
    expiry datetime,
    approved_routes text,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime,
    CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);

CREATE TABLE policies(
    id integer PRIMARY KEY AUTOINCREMENT,
    data text,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime
);

INSERT INTO users
    (id, name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
VALUES
    (1, 'alice', 'Alice', 'alice@example.com', NULL, 'cli', '', '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL);

INSERT INTO pre_auth_keys
    (id, key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
VALUES
    (1, 'legacy-auth-key', NULL, NULL, 1, 1, 0, 0, '["tag:server"]', NULL, '2026-01-01 00:00:00');

INSERT INTO api_keys
    (id, prefix, hash, expiration, last_seen, created_at)
VALUES
    (1, 'legacy-api-prefix', X'68617368', NULL, NULL, '2026-01-01 00:00:00');

INSERT INTO nodes
    (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
VALUES
    (1, 'mkey:fixture', 'nodekey:fixture', 'discokey:fixture', '["1.2.3.4:41641"]',
     '{"Hostname":"alice-laptop","RoutableIPs":["10.0.0.0/24"]}',
     '100.64.0.10', 'fd7a:115c:a1e0::10', 'alice-laptop', 'alice-laptop',
     1, 'authkey', '["tag:server"]', 1, '2026-01-01 00:00:00', NULL,
     '["10.0.0.0/24"]', '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL);

INSERT INTO policies
    (id, data, created_at, updated_at, deleted_at)
VALUES
    (1, '{"acls":[]}', '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL);
"#;

async fn file_db() -> (TempDir, Database) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("headscale-go.sqlite");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let db = Database::new(&url).await.expect("open file db");
    (dir, db)
}

async fn seed_headscale_go_v028_fixture(db: &Database) {
    sqlx::raw_sql(HEADSCALE_GO_V028_FIXTURE)
        .execute(db.pool())
        .await
        .expect("seed headscale-go v0.28 fixture");
}

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
async fn accepts_existing_headscale_go_v028_rows_and_marks_rust_managed_after_migration() {
    let (_dir, db) = file_db().await;
    seed_headscale_go_v028_fixture(&db).await;

    let before = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check import compatibility");
    assert!(matches!(
        before,
        HeadscaleGoImportCompatibility::GoMigrations { .. }
    ));

    db.migrate()
        .await
        .expect("migrate imported headscale-go db");

    let user = users::get_by_name(db.pool(), "alice")
        .await
        .expect("read imported user");
    assert_eq!(user.email, "alice@example.com");

    let preauth = preauth_keys::get_by_id(db.pool(), 1)
        .await
        .expect("read imported preauth key");
    assert_eq!(preauth.user_id, "1");
    assert_eq!(preauth.tag_list(), vec!["tag:server"]);

    let node = headscale_nodes::get_by_id(db.pool(), 1)
        .await
        .expect("read imported node");
    assert_eq!(node.given_name, "alice-laptop");
    assert_eq!(node.tag_list(), vec!["tag:server"]);
    assert_eq!(node.approved_route_list(), vec!["10.0.0.0/24"]);
    assert_eq!(
        node.host_info_value()["RoutableIPs"],
        serde_json::json!(["10.0.0.0/24"])
    );

    let policy = headscale_db::policies::get_latest(db.pool())
        .await
        .expect("query imported policy")
        .expect("imported policy");
    assert_eq!(policy.data, r#"{"acls":[]}"#);

    let after = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check post-migration compatibility");
    assert_eq!(after, HeadscaleGoImportCompatibility::RustManaged);

    db.migrate()
        .await
        .expect("repeat migration stays idempotent");
}

#[tokio::test]
async fn accepts_database_versions_for_v028_compatible_schema() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.28.1-beta.1', '2026-05-22 00:00:00');
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed database_versions");

    let status = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check import compatibility");
    assert_eq!(
        status,
        HeadscaleGoImportCompatibility::Versioned {
            stored_version: "v0.28.1-beta.1".into()
        }
    );

    db.migrate()
        .await
        .expect("v0.28 database_versions row is accepted");
}

#[tokio::test]
async fn rejects_database_versions_from_newer_headscale_go() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.29.0-beta.1', '2026-05-22 00:00:00');
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed database_versions");

    let err = db.migrate().await.expect_err("future Go DB is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(err.to_string().contains("newer headscale-go"));
}

#[tokio::test]
async fn rejects_empty_database_versions_for_untracked_go_shape() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed empty database_versions and Go-shaped table");

    let err = db
        .migrate()
        .await
        .expect_err("untracked Go-shaped DB is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(err.to_string().contains("database_versions is empty"));
}

#[tokio::test]
async fn rejects_unversioned_go_history_before_v028_schema_marker() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202312101416');
        INSERT INTO migrations VALUES('202312101430');
        INSERT INTO migrations VALUES('202402151347');
        INSERT INTO migrations VALUES('202501221827');
        INSERT INTO migrations VALUES('202502131714');
        INSERT INTO migrations VALUES('202511122344-remove-newline-index');
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed old migrations table");

    let err = db.migrate().await.expect_err("pre-v0.28 Go DB is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(
        err.to_string()
            .contains("202601121700-migrate-hostinfo-request-tags")
    );
}

#[tokio::test]
async fn destroy_user_removes_target_users_preauth_keys() {
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
            .fetch_optional(db.pool())
            .await
            .expect("query preauth key after user delete");
    assert_eq!(
        stale_user_id, None,
        "DestroyUser deletes the target user's pre-auth keys before deleting the user"
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
