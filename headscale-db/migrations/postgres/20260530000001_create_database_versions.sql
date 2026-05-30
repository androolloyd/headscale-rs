-- Minimal Postgres parity foundation.
--
-- This intentionally creates only the version guard table. The server runtime
-- and higher-level stores remain SQLite-only until broader Postgres parity is
-- implemented.
CREATE TABLE IF NOT EXISTS database_versions (
    id BIGINT PRIMARY KEY,
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ
);
