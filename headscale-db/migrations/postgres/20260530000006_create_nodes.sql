-- Headscale-go-compatible nodes table for Postgres.
--
-- Current Rust runtime stores approved route state directly in
-- nodes.approved_routes after migrating legacy Go `routes` rows on SQLite.
CREATE TABLE IF NOT EXISTS nodes (
    id              BIGSERIAL PRIMARY KEY,
    machine_key     TEXT,
    node_key        TEXT,
    disco_key       TEXT,
    endpoints       TEXT,
    host_info       TEXT,
    ipv4            TEXT,
    ipv6            TEXT,
    hostname        TEXT,
    given_name      VARCHAR(63),
    user_id         BIGINT,
    register_method TEXT,
    tags            TEXT,
    auth_key_id     BIGINT,
    expiry          TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    approved_routes TEXT,
    created_at      TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,
    CONSTRAINT fk_nodes_user
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_nodes_auth_key
        FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id)
);

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
