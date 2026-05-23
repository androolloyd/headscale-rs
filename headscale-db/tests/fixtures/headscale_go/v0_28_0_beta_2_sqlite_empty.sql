-- Minimal SQLite dump shape from headscale-go v0.28.0-beta.2.
-- beta.2 already includes the RequestTags migration marker required by
-- headscale-rs for v0.28-compatible imports.
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
CREATE TABLE api_keys(
    id integer PRIMARY KEY AUTOINCREMENT,
    prefix text,
    hash blob,
    expiration datetime,
    last_seen datetime,
    created_at datetime
);
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
    deleted_at datetime
);
CREATE TABLE policies(
    id integer PRIMARY KEY AUTOINCREMENT,
    data text,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime
);
