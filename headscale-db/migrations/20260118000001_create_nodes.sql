-- Nodes table - stores registered mesh nodes
CREATE TABLE IF NOT EXISTS nodes (
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
CREATE INDEX IF NOT EXISTS idx_nodes_wg_pubkey ON nodes(wg_pubkey);

-- Index for capability queries
CREATE INDEX IF NOT EXISTS idx_nodes_capabilities ON nodes(
    cap_relay, cap_inference, cap_storage, cap_compute, cap_seed
);

-- Index for online nodes
CREATE INDEX IF NOT EXISTS idx_nodes_online ON nodes(online, last_seen);
