-- Rust/Octra persistence lives in an attached database so the primary SQLite
-- file retains the exact headscale-go v0.29.5 schema.
CREATE TABLE IF NOT EXISTS rust_aux.octra_nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    wg_pubkey TEXT NOT NULL UNIQUE,
    addresses TEXT NOT NULL,
    endpoints TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    online BOOLEAN NOT NULL DEFAULT 1,
    cap_relay BOOLEAN NOT NULL DEFAULT 0,
    cap_inference BOOLEAN NOT NULL DEFAULT 0,
    cap_storage BOOLEAN NOT NULL DEFAULT 0,
    cap_compute BOOLEAN NOT NULL DEFAULT 0,
    cap_seed BOOLEAN NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_octra_nodes_wg_pubkey ON octra_nodes(wg_pubkey);
CREATE INDEX IF NOT EXISTS rust_aux.idx_octra_nodes_capabilities ON octra_nodes(
    cap_relay, cap_inference, cap_storage, cap_compute, cap_seed
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_octra_nodes_online ON octra_nodes(online, last_seen);

CREATE TABLE IF NOT EXISTS rust_aux.transactions (
    id TEXT PRIMARY KEY,
    from_account TEXT NOT NULL,
    to_account TEXT NOT NULL,
    amount INTEGER NOT NULL,
    description TEXT NOT NULL,
    tx_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_transactions_from ON transactions(from_account, timestamp DESC);
CREATE INDEX IF NOT EXISTS rust_aux.idx_transactions_to ON transactions(to_account, timestamp DESC);
CREATE INDEX IF NOT EXISTS rust_aux.idx_transactions_timestamp ON transactions(timestamp DESC);
CREATE INDEX IF NOT EXISTS rust_aux.idx_transactions_type ON transactions(tx_type);

CREATE TABLE IF NOT EXISTS rust_aux.account_balances (
    account TEXT PRIMARY KEY,
    balance INTEGER NOT NULL DEFAULT 0,
    credit_limit INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS rust_aux.resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_spec TEXT NOT NULL,
    pricing TEXT NOT NULL,
    available BOOLEAN NOT NULL DEFAULT 1,
    last_updated INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_resources_provider ON resources(provider);
CREATE INDEX IF NOT EXISTS rust_aux.idx_resources_type ON resources(resource_type, available);

CREATE TABLE IF NOT EXISTS rust_aux.resource_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL,
    resource_spec TEXT NOT NULL,
    consumer TEXT NOT NULL,
    provider TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    units_consumed INTEGER NOT NULL DEFAULT 0,
    cost_millitokens INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_usage_consumer ON resource_usage(consumer, started_at DESC);
CREATE INDEX IF NOT EXISTS rust_aux.idx_usage_provider ON resource_usage(provider, started_at DESC);
CREATE INDEX IF NOT EXISTS rust_aux.idx_usage_active ON resource_usage(ended_at) WHERE ended_at IS NULL;

CREATE TABLE IF NOT EXISTS rust_aux.sessions (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    capabilities TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rust_aux.idx_sessions_did ON sessions(did);
CREATE INDEX IF NOT EXISTS rust_aux.idx_sessions_expiry ON sessions(expires_at);
CREATE TRIGGER IF NOT EXISTS rust_aux.cleanup_expired_sessions
AFTER INSERT ON sessions
BEGIN
    DELETE FROM sessions WHERE expires_at < unixepoch();
END;
