-- Align `pre_auth_keys.user_id` with headscale-go v0.28.0.
--
-- `nodes.auth_key_id` references `pre_auth_keys`, so rebuild the two
-- tables together. Rebuilding only `pre_auth_keys` would cause SQLite to
-- rewrite the existing `nodes` FK to the temporary table name.
DROP INDEX IF EXISTS idx_nodes_given_name;
DROP INDEX IF EXISTS idx_nodes_user_id;
DROP INDEX IF EXISTS idx_nodes_auth_key_id;
DROP INDEX IF EXISTS idx_nodes_deleted_at;
DROP INDEX IF EXISTS idx_nodes_ipv4;
DROP INDEX IF EXISTS idx_nodes_ipv6;
DROP INDEX IF EXISTS idx_pre_auth_keys_user_id;
DROP INDEX IF EXISTS idx_pre_auth_keys_expiration;
DROP INDEX IF EXISTS idx_pre_auth_keys_prefix;

ALTER TABLE nodes RENAME TO nodes_old;
ALTER TABLE pre_auth_keys RENAME TO pre_auth_keys_old;

CREATE TABLE pre_auth_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT,
    prefix     TEXT,
    hash       BLOB,
    user_id    INTEGER,
    reusable   NUMERIC DEFAULT false,
    ephemeral  NUMERIC DEFAULT false,
    used       NUMERIC DEFAULT false,
    tags       TEXT,
    expiration DATETIME,
    created_at DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO pre_auth_keys (
    id,
    key,
    prefix,
    hash,
    user_id,
    reusable,
    ephemeral,
    used,
    tags,
    expiration,
    created_at
)
SELECT
    id,
    key,
    prefix,
    hash,
    COALESCE(
        (
            SELECT users.id
            FROM users
            WHERE CAST(users.id AS TEXT) = CAST(pre_auth_keys_old.user_id AS TEXT)
            LIMIT 1
        ),
        (
            SELECT users.id
            FROM users
            WHERE users.name = CAST(pre_auth_keys_old.user_id AS TEXT)
            LIMIT 1
        )
    ) AS user_id,
    reusable,
    ephemeral,
    used,
    tags,
    expiration,
    created_at
FROM pre_auth_keys_old;

CREATE TABLE nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_key     TEXT,
    node_key        TEXT,
    disco_key       TEXT,
    endpoints       TEXT,
    host_info       TEXT,
    ipv4            TEXT,
    ipv6            TEXT,
    hostname        TEXT,
    given_name      varchar(63),
    user_id         INTEGER,
    register_method TEXT,
    tags            TEXT,
    auth_key_id     INTEGER,
    expiry          DATETIME,
    last_seen       DATETIME,
    approved_routes TEXT,
    created_at      DATETIME,
    updated_at      DATETIME,
    deleted_at      DATETIME,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);

INSERT INTO nodes (
    id,
    machine_key,
    node_key,
    disco_key,
    endpoints,
    host_info,
    ipv4,
    ipv6,
    hostname,
    given_name,
    user_id,
    register_method,
    tags,
    auth_key_id,
    expiry,
    last_seen,
    approved_routes,
    created_at,
    updated_at,
    deleted_at
)
SELECT
    id,
    machine_key,
    node_key,
    disco_key,
    endpoints,
    host_info,
    ipv4,
    ipv6,
    hostname,
    given_name,
    COALESCE(
        (
            SELECT users.id
            FROM users
            WHERE CAST(users.id AS TEXT) = CAST(nodes_old.user_id AS TEXT)
            LIMIT 1
        ),
        (
            SELECT users.id
            FROM users
            WHERE users.name = CAST(nodes_old.user_id AS TEXT)
            LIMIT 1
        )
    ) AS user_id,
    register_method,
    tags,
    CASE
        WHEN auth_key_id IS NOT NULL
             AND EXISTS (SELECT 1 FROM pre_auth_keys WHERE pre_auth_keys.id = nodes_old.auth_key_id)
        THEN auth_key_id
        ELSE NULL
    END AS auth_key_id,
    expiry,
    last_seen,
    approved_routes,
    created_at,
    updated_at,
    deleted_at
FROM nodes_old;

DROP TABLE nodes_old;
DROP TABLE pre_auth_keys_old;

CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_user_id ON pre_auth_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_pre_auth_keys_expiration ON pre_auth_keys(expiration);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pre_auth_keys_prefix
    ON pre_auth_keys(prefix)
    WHERE prefix IS NOT NULL AND prefix != '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_given_name
    ON nodes(given_name)
    WHERE given_name IS NOT NULL AND given_name != '';
CREATE INDEX IF NOT EXISTS idx_nodes_user_id ON nodes(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_auth_key_id ON nodes(auth_key_id);
CREATE INDEX IF NOT EXISTS idx_nodes_deleted_at ON nodes(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_ipv4
    ON nodes(ipv4)
    WHERE ipv4 IS NOT NULL AND ipv4 != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_ipv6
    ON nodes(ipv6)
    WHERE ipv6 IS NOT NULL AND ipv6 != '';
