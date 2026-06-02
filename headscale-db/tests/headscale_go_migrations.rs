use headscale_db::{
    DATABASE_BACKEND_MATRIX, Database, DatabaseBackend, DbError, HEADSCALE_GO_CURRENT_VERSION,
    HeadscaleGoImportCompatibility, api_keys, headscale_nodes,
    preauth_keys::{self, CreateParams as PreauthCreateParams},
    users::{self, CreateParams as UserCreateParams},
};
use tempfile::TempDir;

const LEGACY_ROUTES_MIGRATION: &str =
    include_str!("../migrations/20260522000010_migrate_legacy_routes.sql");
const PREAUTH_USER_FK_MIGRATION: &str =
    include_str!("../migrations/20260523000012_preauth_user_fk.sql");
const CLEAR_TAGGED_NODE_USER_ID_MIGRATION: &str =
    include_str!("../migrations/20260524000014_clear_tagged_node_user_id.sql");
const CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION: &str =
    include_str!("../migrations/20260530000015_clear_zero_time_node_expiry.sql");
const HEADSCALE_GO_V028_AUTH_ROWS_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_28_0_sqlite_auth_rows.sql");
const HEADSCALE_GO_V028_REQUEST_TAGS_ROWS_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_28_0_sqlite_request_tags_rows.sql");
const HEADSCALE_GO_V0260_EMPTY_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_26_0_sqlite_empty.sql");
const HEADSCALE_GO_V0271_EMPTY_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_27_1_sqlite_empty.sql");
const HEADSCALE_GO_V0280_BETA1_EMPTY_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_28_0_beta_1_sqlite_empty.sql");
const HEADSCALE_GO_V0280_BETA2_EMPTY_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_28_0_beta_2_sqlite_empty.sql");
const HEADSCALE_GO_V0280_EMPTY_FIXTURE: &str =
    include_str!("fixtures/headscale_go/v0_28_0_sqlite_empty.sql");
const MODERN_PREAUTH_TOKEN: &str = concat!(
    "hskey-auth-AuthPrefix01-",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
const WRONG_MODERN_PREAUTH_TOKEN: &str = concat!(
    "hskey-auth-AuthPrefix01-",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
);
const MODERN_API_KEY: &str = concat!(
    "hskey-api-ApiPrefix001-",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
);
const WRONG_MODERN_API_KEY: &str = concat!(
    "hskey-api-ApiPrefix001-",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
);

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
    seed_fixture(db, HEADSCALE_GO_V028_FIXTURE, "headscale-go v0.28 fixture").await;
}

async fn seed_headscale_go_v028_auth_rows_fixture(db: &Database) {
    seed_fixture(
        db,
        HEADSCALE_GO_V028_AUTH_ROWS_FIXTURE,
        "headscale-go v0.28 auth rows fixture",
    )
    .await;
}

async fn seed_fixture(db: &Database, fixture: &str, description: &str) {
    sqlx::raw_sql(fixture)
        .execute(db.pool())
        .await
        .unwrap_or_else(|e| panic!("seed {description}: {e}"));
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(db.pool())
        .await
        .unwrap_or_else(|e| panic!("reenable foreign keys after {description}: {e}"));
}

async fn sqlite_table_exists(db: &Database, table: &str) -> bool {
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        ",
    )
    .bind(table)
    .fetch_one(db.pool())
    .await
    .expect("query sqlite schema");

    count > 0
}

fn is_foreign_key_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db) if db.is_foreign_key_violation())
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
async fn database_backend_matrix_is_sqlite_only_for_headscale_db() {
    let sqlite = DATABASE_BACKEND_MATRIX
        .iter()
        .find(|entry| entry.upstream_name == "sqlite3")
        .expect("sqlite backend matrix entry");
    assert!(sqlite.headscale_go_supported);
    assert!(sqlite.headscale_db_supported);
    assert!(sqlite.sqlite_import_supported);
    assert_eq!(sqlite.url_schemes, &["sqlite"]);
    assert_eq!(
        DatabaseBackend::from_url_scheme(sqlite.url_schemes[0]),
        Some(DatabaseBackend::Sqlite)
    );

    let postgres = DATABASE_BACKEND_MATRIX
        .iter()
        .find(|entry| entry.upstream_name == "postgres")
        .expect("postgres backend matrix entry");
    assert!(postgres.headscale_go_supported);
    assert!(!postgres.headscale_db_supported);
    assert!(!postgres.sqlite_import_supported);
    assert_eq!(postgres.url_schemes, &["postgres", "postgresql"]);

    let db = Database::new("sqlite::memory:")
        .await
        .expect("sqlite URL is supported");
    assert_eq!(db.backend(), DatabaseBackend::Sqlite);
    db.close().await;

    let Err(postgres_err) = Database::new("postgres://localhost/headscale").await else {
        panic!("postgres URL should be rejected by headscale-db");
    };
    assert!(matches!(
        postgres_err,
        DbError::UnsupportedDatabaseBackend(_)
    ));
    assert!(postgres_err.to_string().contains("SQLite URLs only"));
}

#[tokio::test]
async fn headscale_go_sqlite_release_fixture_matrix_matches_supported_import_window() {
    struct Case {
        name: &'static str,
        fixture: &'static str,
        supported: bool,
        error_contains: &'static str,
    }

    let cases = [
        Case {
            name: "v0.26.0",
            fixture: HEADSCALE_GO_V0260_EMPTY_FIXTURE,
            supported: false,
            error_contains: "upgrade with headscale-go v0.28.0",
        },
        Case {
            name: "v0.27.1",
            fixture: HEADSCALE_GO_V0271_EMPTY_FIXTURE,
            supported: false,
            error_contains: "202601121700-migrate-hostinfo-request-tags",
        },
        Case {
            name: "v0.28.0-beta.1",
            fixture: HEADSCALE_GO_V0280_BETA1_EMPTY_FIXTURE,
            supported: false,
            error_contains: "202601121700-migrate-hostinfo-request-tags",
        },
        Case {
            name: "v0.28.0-beta.2",
            fixture: HEADSCALE_GO_V0280_BETA2_EMPTY_FIXTURE,
            supported: true,
            error_contains: "",
        },
        Case {
            name: "v0.28.0",
            fixture: HEADSCALE_GO_V0280_EMPTY_FIXTURE,
            supported: true,
            error_contains: "",
        },
    ];

    for case in cases {
        let (_dir, db) = file_db().await;
        seed_fixture(&db, case.fixture, case.name).await;

        if case.supported {
            let before = db
                .check_headscale_go_import_compatibility()
                .await
                .unwrap_or_else(|e| panic!("{} should be import-compatible: {e}", case.name));
            assert!(matches!(
                before,
                HeadscaleGoImportCompatibility::GoMigrations { .. }
            ));

            db.migrate()
                .await
                .unwrap_or_else(|e| panic!("{} should migrate: {e}", case.name));

            let after = db
                .check_headscale_go_import_compatibility()
                .await
                .expect("check post-migration compatibility");
            assert_eq!(after, HeadscaleGoImportCompatibility::RustManaged);
        } else {
            let err = match db.migrate().await {
                Ok(()) => panic!("{} should be rejected", case.name),
                Err(err) => err,
            };
            assert!(matches!(
                err,
                DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
            ));
            assert!(
                err.to_string().contains(case.error_contains),
                "{} error should mention {:?}, got {err}",
                case.name,
                case.error_contains
            );
            assert!(
                !sqlite_table_exists(&db, "_sqlx_migrations").await,
                "{} should be rejected before sqlx migrations run",
                case.name
            );
        }
    }
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
    assert_eq!(node.user_id, None);
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
async fn imports_headscale_go_v028_modern_auth_rows() {
    let (_dir, db) = file_db().await;
    seed_headscale_go_v028_auth_rows_fixture(&db).await;

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

    assert!(
        api_keys::validate(db.pool(), MODERN_API_KEY)
            .await
            .expect("modern imported API key validates")
    );
    let api_err = api_keys::validate(db.pool(), WRONG_MODERN_API_KEY)
        .await
        .expect_err("wrong modern API key secret is rejected");
    assert!(matches!(api_err, api_keys::ApiKeyError::Invalid));
    let api_key = api_keys::get_by_prefix(db.pool(), "ApiPrefix001")
        .await
        .expect("read imported API key");
    assert!(api_key.secret_hash.starts_with("$2b$04$"));
    assert_eq!(api_key.expiration, Some(1_893_456_000));
    assert_eq!(api_key.last_seen, Some(1_767_323_045));
    assert_eq!(api_key.created_at, 1_767_225_600);
    assert_eq!(api_key.display_prefix(), "hskey-api-ApiPrefix001-***");

    let preauth = preauth_keys::get_by_token(db.pool(), MODERN_PREAUTH_TOKEN)
        .await
        .expect("modern imported preauth key validates");
    let preauth_err = preauth_keys::get_by_token(db.pool(), WRONG_MODERN_PREAUTH_TOKEN)
        .await
        .expect_err("wrong modern preauth secret is rejected");
    assert!(matches!(
        preauth_err,
        DbError::General(msg) if msg.contains("invalid auth key")
    ));
    assert!(preauth.key.is_none());
    assert_eq!(preauth.user_id, "1");
    assert_eq!(preauth.prefix.as_deref(), Some("AuthPrefix01"));
    assert_eq!(preauth.display_key(), "hskey-auth-AuthPrefix01-***");
    assert!(preauth.key_hash.starts_with("$2b$04$"));
    assert_eq!(preauth.tag_list(), vec!["tag:server"]);
    assert!(preauth.ephemeral);
    assert!(!preauth.reusable);
    assert!(!preauth.is_used());
    assert!(preauth.is_live(1_767_323_045));
    assert_eq!(preauth.created_at, 1_767_225_600);
    assert_eq!(preauth.expiration, None);

    let node = headscale_nodes::get_by_id(db.pool(), 1)
        .await
        .expect("read imported node");
    assert_eq!(node.machine_key, "mkey:modern");
    assert_eq!(node.node_key, "nodekey:modern");
    assert_eq!(node.disco_key, "discokey:modern");
    assert_eq!(node.user_id, None);
    assert_eq!(
        node.register_method,
        headscale_nodes::REGISTER_METHOD_AUTH_KEY
    );
    assert_eq!(node.auth_key_id, Some(preauth.id));
    assert_eq!(node.hostname, "alice-router");
    assert_eq!(node.given_name, "alice-router");
    assert_eq!(node.ipv4.as_deref(), Some("100.64.0.10"));
    assert_eq!(node.ipv6.as_deref(), Some("fd7a:115c:a1e0::10"));
    assert_eq!(
        node.endpoint_list(),
        vec!["1.2.3.4:41641", "[2001:db8::1]:41641"]
    );
    assert_eq!(node.tag_list(), vec!["tag:server"]);
    assert_eq!(node.approved_route_list(), vec!["10.0.0.0/24"]);
    assert_eq!(node.host_info_value()["NetInfo"]["PreferredDERP"], 901);
    assert_eq!(
        node.host_info_value()["RequestTags"],
        serde_json::json!(["tag:server"])
    );
    assert_eq!(
        node.expiry, None,
        "Go zero-time node expiry imports as non-expiring"
    );
    assert_eq!(node.last_seen, Some(1_767_323_045));
    assert_eq!(node.created_at, 1_767_225_600);
    assert_eq!(node.updated_at, 1_767_225_600);
    assert_eq!(node.deleted_at, None);

    let linked_metadata: (String, String) = sqlx::query_as(
        "
        SELECT pre_auth_keys.prefix, nodes.register_method
        FROM nodes
        JOIN pre_auth_keys ON pre_auth_keys.id = nodes.auth_key_id
        WHERE nodes.id = 1
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("linked auth-key node metadata");
    assert_eq!(
        linked_metadata,
        (
            "AuthPrefix01".to_string(),
            headscale_nodes::REGISTER_METHOD_AUTH_KEY.to_string()
        )
    );

    let policy = headscale_db::policies::get_latest(db.pool())
        .await
        .expect("query imported policy")
        .expect("imported policy");
    assert_eq!(policy.data, r#"{"tagOwners":{"tag:server":["alice@"]}}"#);

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
async fn imports_request_tags_migration_outcome_and_applies_current_node_migrations() {
    let (_dir, db) = file_db().await;
    seed_fixture(
        &db,
        HEADSCALE_GO_V028_REQUEST_TAGS_ROWS_FIXTURE,
        "headscale-go request-tags rows fixture",
    )
    .await;

    let before = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check import compatibility");
    assert!(matches!(
        before,
        HeadscaleGoImportCompatibility::GoMigrations { required_migration }
            if required_migration == "202601121700-migrate-hostinfo-request-tags"
    ));

    db.migrate()
        .await
        .expect("migrate imported headscale-go request-tags db");

    let mixed = headscale_nodes::get_by_id(db.pool(), 1)
        .await
        .expect("read mixed RequestTags node");
    assert_eq!(
        mixed.host_info_value()["RequestTags"],
        serde_json::json!(["tag:server", "tag:db"])
    );
    assert_eq!(
        mixed.tag_list(),
        vec!["tag:server"],
        "authorized RequestTags are present in nodes.tags and unauthorized tags are skipped"
    );
    assert_eq!(
        mixed.user_id, None,
        "tagged nodes are tag-owned after the current upstream user_id migration"
    );
    assert_eq!(
        mixed.expiry, None,
        "Go zero-time node expiry reads as non-expiring after import"
    );
    let mixed_raw_expiry: Option<String> =
        sqlx::query_scalar("SELECT expiry FROM nodes WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("query raw mixed node expiry");
    assert_eq!(
        mixed_raw_expiry, None,
        "Go zero-time node expiry is normalized to SQL NULL"
    );

    let denied = headscale_nodes::get_by_id(db.pool(), 2)
        .await
        .expect("read denied RequestTags node");
    assert_eq!(
        denied.host_info_value()["RequestTags"],
        serde_json::json!(["tag:db"])
    );
    assert!(
        denied.tag_list().is_empty(),
        "unauthorized-only RequestTags do not populate nodes.tags"
    );
    assert_eq!(denied.user_id, Some(1), "untagged nodes remain user-owned");
    assert_eq!(denied.expiry, None);

    let policy = headscale_db::policies::get_latest(db.pool())
        .await
        .expect("query imported policy")
        .expect("imported policy");
    assert_eq!(policy.data, r#"{"tagOwners":{"tag:server":["alice@"]}}"#);

    let after = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check post-migration compatibility");
    assert_eq!(after, HeadscaleGoImportCompatibility::RustManaged);
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

    let stored_version: String =
        sqlx::query_scalar("SELECT version FROM database_versions WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("query stamped database_versions row");
    assert_eq!(stored_version, HEADSCALE_GO_CURRENT_VERSION);

    let after = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check post-migration compatibility");
    assert_eq!(after, HeadscaleGoImportCompatibility::RustManaged);
}

#[tokio::test]
async fn accepts_current_database_versions_with_beta2_migration_history() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.29.0-beta.2', '2026-05-22 00:00:00');
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');
        INSERT INTO migrations VALUES('202602201200-clear-tagged-node-user-id');
        INSERT INTO migrations VALUES('202605221435-clear-zero-time-node-expiry');
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed current database_versions plus migrations");

    let status = db
        .check_headscale_go_import_compatibility()
        .await
        .expect("check import compatibility");
    assert_eq!(
        status,
        HeadscaleGoImportCompatibility::Versioned {
            stored_version: "v0.29.0-beta.2".into()
        }
    );
}

#[tokio::test]
async fn rejects_current_database_versions_without_tagged_node_migration_history() {
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
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed current database_versions without current migration");

    let err = db
        .migrate()
        .await
        .expect_err("current Go DB without current migration marker is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(
        err.to_string()
            .contains("202602201200-clear-tagged-node-user-id")
    );
}

#[tokio::test]
async fn rejects_current_database_versions_without_zero_time_expiry_migration_history() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.29.0-beta.2', '2026-05-22 00:00:00');
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');
        INSERT INTO migrations VALUES('202602201200-clear-tagged-node-user-id');
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed current database_versions without zero-time expiry migration");

    let err = db
        .migrate()
        .await
        .expect_err("current Go DB without beta.2 migration marker is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(
        err.to_string()
            .contains("202605221435-clear-zero-time-node-expiry")
    );
}

#[tokio::test]
async fn rejects_current_database_versions_without_v028_baseline_history() {
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
        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202602201200-clear-tagged-node-user-id');
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed current database_versions without v0.28 baseline migration");

    let err = db
        .migrate()
        .await
        .expect_err("current Go DB without v0.28 baseline marker is rejected");
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
async fn database_versions_v028_accepts_current_tagged_node_user_migration() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, 'v0.28.0', '2026-05-22 00:00:00');

        CREATE TABLE migrations(id text, PRIMARY KEY(id));
        INSERT INTO migrations VALUES('202601121700-migrate-hostinfo-request-tags');
        INSERT INTO migrations VALUES('202602201200-clear-tagged-node-user-id');
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
        INSERT INTO users (id, name, display_name, email, provider, profile_pic_url, created_at, updated_at)
            VALUES (1, 'alice', 'Alice', 'alice@example.com', 'cli', '', datetime('now'), datetime('now'));
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
            given_name text,
            user_id integer,
            register_method text,
            tags text,
            auth_key_id integer,
            expiry datetime,
            last_seen datetime,
            approved_routes text,
            created_at datetime,
            updated_at datetime,
            deleted_at datetime
        );
        INSERT INTO nodes
            (id, machine_key, node_key, disco_key, endpoints, host_info, hostname, given_name,
             user_id, register_method, tags, approved_routes, created_at, updated_at)
        VALUES
            (1, 'mkey:tagged', 'nodekey:tagged', 'discokey:tagged', '[]', '{}',
             'tagged', 'tagged', 1, 'authkey', '[\"tag:server\"]', '[]',
             datetime('now'), datetime('now')),
            (2, 'mkey:user', 'nodekey:user', 'discokey:user', '[]', '{}',
             'user-node', 'user-node', 1, 'authkey', '[]', '[]',
             datetime('now'), datetime('now'));
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed database_versions plus current migration history");

    db.migrate()
        .await
        .expect("current tagged-node user migration is accepted");

    let tagged_user_id: Option<i64> = sqlx::query_scalar("SELECT user_id FROM nodes WHERE id = 1")
        .fetch_one(db.pool())
        .await
        .expect("query tagged node");
    assert_eq!(tagged_user_id, None);

    let user_node_user_id: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM nodes WHERE id = 2")
            .fetch_one(db.pool())
            .await
            .expect("query user-owned node");
    assert_eq!(user_node_user_id, Some(1));
}

#[tokio::test]
async fn development_database_versions_require_supported_go_migration_history_for_go_shape() {
    let (_dir, db) = file_db().await;
    sqlx::raw_sql(
        "
        CREATE TABLE database_versions(
            id integer PRIMARY KEY,
            version text NOT NULL,
            updated_at datetime
        );
        INSERT INTO database_versions (id, version, updated_at)
            VALUES (1, '(devel)', '2026-05-22 00:00:00');
        CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed devel database_versions and Go-shaped table");

    let err = db
        .migrate()
        .await
        .expect_err("devel Go-shaped DB without migration history is rejected");
    assert!(matches!(
        err,
        DbError::UnsupportedHeadscaleGoDatabaseVersion(_)
    ));
    assert!(
        err.to_string()
            .contains("without supported headscale-go migration history")
    );
}

#[tokio::test]
async fn node_uniqueness_indexes_are_partial() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");

    let indexes: Vec<(String, String)> = sqlx::query_as(
        "
        SELECT name, sql
        FROM sqlite_master
        WHERE type = 'index'
          AND name IN ('idx_nodes_ipv4', 'idx_nodes_ipv6', 'idx_nodes_node_key_live')
        ORDER BY name
        ",
    )
    .fetch_all(db.pool())
    .await
    .expect("query node address indexes");

    assert_eq!(indexes.len(), 3);
    assert_eq!(indexes[0].0, "idx_nodes_ipv4");
    assert!(indexes[0].1.contains("UNIQUE INDEX"));
    assert!(
        indexes[0]
            .1
            .contains("WHERE ipv4 IS NOT NULL AND ipv4 != ''")
    );
    assert_eq!(indexes[1].0, "idx_nodes_ipv6");
    assert!(indexes[1].1.contains("UNIQUE INDEX"));
    assert!(
        indexes[1]
            .1
            .contains("WHERE ipv6 IS NOT NULL AND ipv6 != ''")
    );
    assert_eq!(indexes[2].0, "idx_nodes_node_key_live");
    assert!(indexes[2].1.contains("UNIQUE INDEX"));
    assert!(
        indexes[2]
            .1
            .contains("WHERE node_key IS NOT NULL AND node_key != '' AND deleted_at IS NULL")
    );
}

#[tokio::test]
async fn nodes_given_name_column_matches_headscale_go_type() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");

    let column_type: String = sqlx::query_scalar(
        "
        SELECT type
        FROM pragma_table_info('nodes')
        WHERE name = 'given_name'
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("query nodes.given_name type");

    assert_eq!(column_type, "varchar(63)");
}

#[tokio::test]
async fn fresh_rust_migration_stamps_current_database_versions_row() {
    let (_dir, db) = file_db().await;
    db.migrate().await.expect("migrate");

    assert!(sqlite_table_exists(&db, "database_versions").await);
    let row: (i64, String, i64) = sqlx::query_as(
        "
        SELECT id, version, updated_at IS NOT NULL
        FROM database_versions
        ",
    )
    .fetch_one(db.pool())
    .await
    .expect("query database_versions");
    assert_eq!(row, (1, HEADSCALE_GO_CURRENT_VERSION.to_string(), 1));
}

#[tokio::test]
async fn clear_tagged_node_user_id_migration_preserves_untagged_nodes() {
    let db = Database::in_memory().await.expect("open db");
    sqlx::raw_sql(
        "
        CREATE TABLE nodes(
            id integer PRIMARY KEY AUTOINCREMENT,
            user_id integer,
            tags text
        );
        INSERT INTO nodes (id, user_id, tags)
        VALUES
            (1, 10, '[\"tag:server\"]'),
            (2, 11, '[]'),
            (3, 12, ''),
            (4, 13, NULL);
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed nodes");

    sqlx::raw_sql(CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
        .execute(db.pool())
        .await
        .expect("run tagged ownership migration");

    let rows: Vec<(i64, Option<i64>)> = sqlx::query_as("SELECT id, user_id FROM nodes ORDER BY id")
        .fetch_all(db.pool())
        .await
        .expect("query nodes");
    assert_eq!(
        rows,
        vec![(1, None), (2, Some(11)), (3, Some(12)), (4, Some(13))]
    );
}

#[tokio::test]
async fn clear_zero_time_node_expiry_migration_preserves_real_expiry_values() {
    let db = Database::in_memory().await.expect("open db");
    sqlx::raw_sql(
        "
        CREATE TABLE nodes(
            id integer PRIMARY KEY AUTOINCREMENT,
            expiry datetime
        );
        INSERT INTO nodes (id, expiry)
        VALUES
            (1, '0001-01-01 00:00:00+00:00'),
            (2, NULL),
            (3, '2099-12-31 23:59:59+00:00'),
            (4, '2020-01-01 00:00:00+00:00'),
            (5, '1899-12-31 23:59:59+00:00');
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed nodes");

    sqlx::raw_sql(CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
        .execute(db.pool())
        .await
        .expect("run zero-time expiry migration");

    let rows: Vec<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, expiry FROM nodes ORDER BY id")
            .fetch_all(db.pool())
            .await
            .expect("query nodes");
    assert_eq!(
        rows,
        vec![
            (1, None),
            (2, None),
            (3, Some("2099-12-31 23:59:59+00:00".into())),
            (4, Some("2020-01-01 00:00:00+00:00".into())),
            (5, None),
        ]
    );
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
            VALUES (1, 'v0.30.0', '2026-05-22 00:00:00');
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
async fn user_node_and_preauth_foreign_keys_match_headscale_go_delete_semantics() {
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
        preauth_user_fks
            .iter()
            .any(|(from, table, to, on_delete)| from == "user_id"
                && table == "users"
                && to == "id"
                && on_delete.eq_ignore_ascii_case("SET NULL")),
        "pre_auth_keys.user_id should match headscale-go's users(id) ON DELETE SET NULL FK"
    );

    let node_fks: Vec<(String, String, String, String)> = sqlx::query_as(
        r#"
        SELECT "from", "table", "to", on_delete
        FROM pragma_foreign_key_list('nodes')
        "#,
    )
    .fetch_all(db.pool())
    .await
    .expect("query nodes foreign keys");
    assert!(
        node_fks
            .iter()
            .any(|(from, table, to, on_delete)| from == "user_id"
                && table == "users"
                && to == "id"
                && on_delete.eq_ignore_ascii_case("CASCADE")),
        "nodes.user_id should match headscale-go's users(id) ON DELETE CASCADE FK"
    );
    assert!(
        node_fks
            .iter()
            .any(|(from, table, to, on_delete)| from == "auth_key_id"
                && table == "pre_auth_keys"
                && to == "id"
                && on_delete.eq_ignore_ascii_case("NO ACTION")),
        "nodes.auth_key_id should match headscale-go's pre_auth_keys(id) NO ACTION FK"
    );

    let missing_user_err = sqlx::query(
        "
        INSERT INTO pre_auth_keys
            (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
        VALUES
            ('missing-user-key', NULL, NULL, 999, false, false, false, '[]', NULL, datetime('now'))
        ",
    )
    .execute(db.pool())
    .await
    .expect_err("preauth keys must reference an existing user");
    assert!(is_foreign_key_violation(&missing_user_err));

    let missing_auth_key_err = sqlx::query(
        "
        INSERT INTO nodes
            (machine_key, node_key, disco_key, endpoints, host_info, hostname, given_name,
             user_id, register_method, tags, auth_key_id, approved_routes, created_at, updated_at)
        VALUES
            ('mkey:missing-auth', 'nodekey:missing-auth', 'discokey:missing-auth', '[]', '{}',
             'missing-auth', 'missing-auth', NULL, 'authkey', '[]', 999, '[]',
             datetime('now'), datetime('now'))
        ",
    )
    .execute(db.pool())
    .await
    .expect_err("nodes must reference an existing auth key");
    assert!(is_foreign_key_violation(&missing_auth_key_err));

    let user_id = user_id(&db).await;
    let auth_key_id = preauth_key_id(&db, user_id).await;
    let node = node_with_route(&db, user_id, auth_key_id).await;

    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(db.pool())
        .await
        .expect("raw user delete applies DB FK actions");

    let preauth_user_id: Option<i64> =
        sqlx::query_scalar("SELECT user_id FROM pre_auth_keys WHERE id = ?")
            .bind(auth_key_id)
            .fetch_one(db.pool())
            .await
            .expect("query preauth key after raw user delete");
    assert_eq!(preauth_user_id, None);
    assert!(matches!(
        headscale_nodes::get_by_id(db.pool(), node.id)
            .await
            .unwrap_err(),
        DbError::NotFound(_)
    ));
}

#[tokio::test]
async fn preauth_user_fk_migration_preserves_legacy_string_user_labels_when_name_exists() {
    let db = Database::in_memory().await.expect("open db");
    sqlx::raw_sql(
        "
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
        INSERT INTO users (id, name, display_name, email, provider, profile_pic_url, created_at, updated_at)
            VALUES (1, 'alice', 'Alice', 'alice@example.com', 'cli', '', datetime('now'), datetime('now'));

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
            created_at datetime
        );
        INSERT INTO pre_auth_keys
            (id, key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
        VALUES
            (1, 'legacy-name-key', NULL, NULL, 'alice', false, false, false, '[]', NULL, datetime('now')),
            (2, 'legacy-missing-key', NULL, NULL, 'missing', false, false, false, '[]', NULL, datetime('now'));

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
            given_name text,
            user_id integer,
            register_method text,
            tags text,
            auth_key_id integer,
            expiry datetime,
            last_seen datetime,
            approved_routes text,
            created_at datetime,
            updated_at datetime,
            deleted_at datetime
        );
        INSERT INTO nodes
            (id, machine_key, node_key, disco_key, endpoints, host_info, hostname, given_name,
             user_id, register_method, tags, auth_key_id, approved_routes, created_at, updated_at)
        VALUES
            (1, 'mkey:legacy', 'nodekey:legacy', 'discokey:legacy', '[]', '{}',
             'legacy', 'legacy', 'alice', 'authkey', '[]', 1, '[]', datetime('now'), datetime('now'));
        ",
    )
    .execute(db.pool())
    .await
    .expect("seed pre-FK schema");

    sqlx::raw_sql(PREAUTH_USER_FK_MIGRATION)
        .execute(db.pool())
        .await
        .expect("run preauth user FK migration");

    let preserved: (Option<i64>, String) =
        sqlx::query_as("SELECT user_id, typeof(user_id) FROM pre_auth_keys WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("query preserved preauth");
    assert_eq!(preserved, (Some(1), "integer".to_string()));

    let missing: Option<i64> = sqlx::query_scalar("SELECT user_id FROM pre_auth_keys WHERE id = 2")
        .fetch_one(db.pool())
        .await
        .expect("query missing-user preauth");
    assert_eq!(missing, None);

    let node_fk: (Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT user_id, auth_key_id FROM nodes WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .expect("query migrated node");
    assert_eq!(node_fk, (Some(1), Some(1)));
}

#[tokio::test]
async fn destroy_user_removes_target_users_preauth_keys() {
    let db = Database::in_memory().await.expect("open db");
    db.migrate().await.expect("migrate");

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
        vec!["0.0.0.0/0", "10.0.0.0/24", "10.1.0.0/24"]
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

#[tokio::test]
async fn migrates_legacy_routes_table_without_synthesizing_opposite_exit_route() {
    for prefix in ["0.0.0.0/0", "::/0"] {
        let db = Database::in_memory().await.expect("open db");
        db.migrate().await.expect("migrate");

        let user_id = user_id(&db).await;
        let auth_key_id = preauth_key_id(&db, user_id).await;
        let node = node_with_route(&db, user_id, auth_key_id).await;

        sqlx::query("UPDATE nodes SET approved_routes = '[]' WHERE id = ?")
            .bind(node.id)
            .execute(db.pool())
            .await
            .expect("clear existing approved routes");

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
            ",
        )
        .execute(db.pool())
        .await
        .expect("create legacy routes table");

        sqlx::query(
            "INSERT INTO routes (node_id, prefix, advertised, enabled, is_primary)
             VALUES (?, ?, 1, 1, 1)",
        )
        .bind(node.id)
        .bind(prefix)
        .execute(db.pool())
        .await
        .expect("seed legacy exit route");

        sqlx::raw_sql(LEGACY_ROUTES_MIGRATION)
            .execute(db.pool())
            .await
            .expect("run legacy routes migration");

        let migrated = headscale_nodes::get_by_id(db.pool(), node.id)
            .await
            .expect("reload node");
        assert_eq!(migrated.approved_route_list(), vec![prefix]);
    }
}
