-- Minimal SQLite dump shape from headscale-go v0.26.0.
-- This release is a supported upstream upgrade source for headscale-go v0.28,
-- but headscale-rs does not run historical Go migrations directly.
CREATE TABLE migrations(id text, PRIMARY KEY(id));
INSERT INTO migrations VALUES('202312101416');
INSERT INTO migrations VALUES('202312101430');
INSERT INTO migrations VALUES('202402151347');
INSERT INTO migrations VALUES('2024041121742');
INSERT INTO migrations VALUES('202406021630');
INSERT INTO migrations VALUES('202409271400');
INSERT INTO migrations VALUES('202407191627');
INSERT INTO migrations VALUES('202408181235');
INSERT INTO migrations VALUES('202501221827');
INSERT INTO migrations VALUES('202501311657');
INSERT INTO migrations VALUES('202502070949');
INSERT INTO migrations VALUES('202502131714');
INSERT INTO migrations VALUES('202502171819');
INSERT INTO migrations VALUES('202505091439');
INSERT INTO migrations VALUES('202505141324');

CREATE TABLE users(id integer PRIMARY KEY AUTOINCREMENT, name text);
CREATE TABLE pre_auth_keys(
    id integer PRIMARY KEY AUTOINCREMENT,
    key text,
    user_id integer,
    reusable numeric,
    ephemeral numeric DEFAULT false,
    used numeric DEFAULT false,
    tags text,
    created_at datetime,
    expiration datetime
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
    forced_tags text,
    auth_key_id integer,
    expiry datetime,
    last_seen datetime,
    approved_routes text,
    created_at datetime,
    updated_at datetime,
    deleted_at datetime
);
