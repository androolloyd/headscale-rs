-- Headscale-go-compatible API keys table for Postgres.
--
-- Upstream plaintext shape is `hskey-api-<12 urlsafe chars>-<64 urlsafe
-- chars>`. The public prefix is stored plainly, and the secret is bcrypt
-- hashed in `hash`.
CREATE TABLE IF NOT EXISTS api_keys (
    id         BIGSERIAL PRIMARY KEY,
    prefix     TEXT,
    hash       BYTEA,
    expiration TIMESTAMPTZ,
    last_seen  TIMESTAMPTZ,
    created_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_expiration ON api_keys(expiration);
