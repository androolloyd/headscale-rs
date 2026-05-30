-- Headscale-go-compatible policy history table for Postgres.
--
-- This mirrors the upstream GORM shape for hscontrol/types/policy.go:
-- standard timestamp/soft-delete columns plus raw HuJSON `data`.
CREATE TABLE IF NOT EXISTS policies (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    data       TEXT
);

CREATE INDEX IF NOT EXISTS idx_policies_deleted_at ON policies(deleted_at);
