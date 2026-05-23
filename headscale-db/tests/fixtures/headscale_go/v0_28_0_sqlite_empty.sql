-- Minimal SQLite dump shape from a fresh headscale-go v0.28.0 database.
-- Fresh v0.28 databases only record the retained migration IDs from the
-- current gormigrate list; upgraded databases can also retain older IDs.
CREATE TABLE migrations(id text, PRIMARY KEY(id));
INSERT INTO migrations VALUES('202501221827');
INSERT INTO migrations VALUES('202501311657');
INSERT INTO migrations VALUES('202502070949');
INSERT INTO migrations VALUES('202502131714');
INSERT INTO migrations VALUES('202502171819');
INSERT INTO migrations VALUES('202505091439');
INSERT INTO migrations VALUES('202505141324');
INSERT INTO migrations VALUES('202507021200');
INSERT INTO migrations VALUES('202510311551');
INSERT INTO migrations VALUES('202511101554-drop-old-idx');
INSERT INTO migrations VALUES('202511011637-preauthkey-bcrypt');
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
