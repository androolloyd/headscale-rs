-- API keys table — mirrors juanfont/headscale v0.28.0 hscontrol/types/api_key.go.
--
-- Upstream plaintext shape is:
--   hskey-api-<12 urlsafe chars>-<64 urlsafe chars>
--
-- The public prefix is stored plainly for lookup/listing. The secret
-- is bcrypt-hashed; plaintext is returned only once on create.
CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix     TEXT,
    hash       BLOB,
    expiration DATETIME,
    last_seen  DATETIME,
    created_at DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_expiration ON api_keys(expiration);
