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
    (1, NULL, 'AuthPrefix01', '$2b$04$5RfO8BdYdKjb49aeqxhdOOojgn0AzTDfnFgGy/RrIUYj37OXUiy5S',
     1, 0, 1, 0, '["tag:server"]', NULL, '2026-01-01 00:00:00');

INSERT INTO api_keys
    (id, prefix, hash, expiration, last_seen, created_at)
VALUES
    (1, 'ApiPrefix001', '$2b$04$rMRfI37l48AqNReGwzr4xu3b0JJDO63bSC40sLOng8XNlXTaYuBbm',
     '2030-01-01 00:00:00', '2026-01-02 03:04:05', '2026-01-01 00:00:00');

INSERT INTO nodes
    (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, last_seen, expiry, approved_routes, created_at, updated_at, deleted_at)
VALUES
    (1, 'mkey:modern', 'nodekey:modern', 'discokey:modern',
     '["1.2.3.4:41641","[2001:db8::1]:41641"]',
     '{"Hostname":"alice-router","RoutableIPs":["10.0.0.0/24"],"RequestTags":["tag:server"],"NetInfo":{"PreferredDERP":901}}',
     '100.64.0.10', 'fd7a:115c:a1e0::10', 'alice-router', 'alice-router',
     1, 'authkey', '["tag:server"]', 1, '2026-01-02 03:04:05',
     '0001-01-01 00:00:00+00:00', '["10.0.0.0/24"]',
     '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL);

INSERT INTO policies
    (id, data, created_at, updated_at, deleted_at)
VALUES
    (1, '{"tagOwners":{"tag:server":["alice@"]}}', '2026-01-01 00:00:00', '2026-01-01 00:00:00', NULL);
