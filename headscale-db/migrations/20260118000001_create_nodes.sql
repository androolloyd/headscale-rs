-- Legacy Octra mesh nodes table. The public headscale-go-compatible
-- table name is `nodes` below; keep this helper table separate so the
-- existing resource/mesh APIs do not occupy the upstream table name.
CREATE TABLE IF NOT EXISTS octra_nodes (
    id TEXT PRIMARY KEY,                    -- Node DID
    name TEXT NOT NULL,                     -- Human-readable name
    wg_pubkey TEXT NOT NULL UNIQUE,         -- WireGuard public key
    addresses TEXT NOT NULL,                -- JSON array of IP addresses
    endpoints TEXT NOT NULL,                -- JSON array of endpoints
    last_seen INTEGER NOT NULL,             -- Unix timestamp
    online BOOLEAN NOT NULL DEFAULT 1,      -- Online status

    -- Capabilities (boolean flags)
    cap_relay BOOLEAN NOT NULL DEFAULT 0,
    cap_inference BOOLEAN NOT NULL DEFAULT 0,
    cap_storage BOOLEAN NOT NULL DEFAULT 0,
    cap_compute BOOLEAN NOT NULL DEFAULT 0,
    cap_seed BOOLEAN NOT NULL DEFAULT 0,

    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Index for lookup by public key
CREATE INDEX IF NOT EXISTS idx_octra_nodes_wg_pubkey ON octra_nodes(wg_pubkey);

-- Index for capability queries
CREATE INDEX IF NOT EXISTS idx_octra_nodes_capabilities ON octra_nodes(
    cap_relay, cap_inference, cap_storage, cap_compute, cap_seed
);

-- Index for online nodes
CREATE INDEX IF NOT EXISTS idx_octra_nodes_online ON octra_nodes(online, last_seen);

-- Headscale-go v0.28-compatible nodes table. Column names mirror
-- hscontrol/types/node.go and GORM's sqlite naming conventions.
CREATE TABLE IF NOT EXISTS nodes (
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
    FOREIGN KEY(auth_key_id) REFERENCES pre_auth_keys(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_given_name
    ON nodes(given_name)
    WHERE given_name IS NOT NULL AND given_name != '';
CREATE INDEX IF NOT EXISTS idx_nodes_user_id ON nodes(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_auth_key_id ON nodes(auth_key_id);
CREATE INDEX IF NOT EXISTS idx_nodes_deleted_at ON nodes(deleted_at);
