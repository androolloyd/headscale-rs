-- Sessions table - stores authenticated sessions
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,                 -- Session token
    did TEXT NOT NULL,                      -- Node DID (no FK for flexibility in auth-only use cases)
    created_at INTEGER NOT NULL,            -- Unix timestamp
    expires_at INTEGER NOT NULL,            -- Unix timestamp
    capabilities TEXT NOT NULL              -- JSON array of capabilities
);

-- Indexes for session queries
CREATE INDEX IF NOT EXISTS idx_sessions_did ON sessions(did);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

-- Cleanup expired sessions trigger
CREATE TRIGGER IF NOT EXISTS cleanup_expired_sessions
AFTER INSERT ON sessions
BEGIN
    DELETE FROM sessions WHERE expires_at < unixepoch();
END;
