-- Align `nodes.auth_key_id` with headscale-go v0.28.0.
--
-- Upstream first clears references to pre-auth keys that were already
-- deleted, then enforces a normal FK so future deletion of an assigned
-- pre-auth key fails instead of silently detaching the node.
DROP INDEX IF EXISTS idx_nodes_given_name;
DROP INDEX IF EXISTS idx_nodes_user_id;
DROP INDEX IF EXISTS idx_nodes_auth_key_id;
DROP INDEX IF EXISTS idx_nodes_deleted_at;

ALTER TABLE nodes RENAME TO nodes_old;

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
    user_id,
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_given_name
    ON nodes(given_name)
    WHERE given_name IS NOT NULL AND given_name != '';
CREATE INDEX IF NOT EXISTS idx_nodes_user_id ON nodes(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_auth_key_id ON nodes(auth_key_id);
CREATE INDEX IF NOT EXISTS idx_nodes_deleted_at ON nodes(deleted_at);
