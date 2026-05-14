-- Resources table - stores available resources from providers
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,                 -- Provider DID
    resource_type TEXT NOT NULL,            -- inference, storage, compute, bandwidth
    resource_spec TEXT NOT NULL,            -- JSON spec (InferenceSpec, StorageSpec, etc.)
    pricing TEXT NOT NULL,                  -- JSON ResourcePricing
    available BOOLEAN NOT NULL DEFAULT 1,
    last_updated INTEGER NOT NULL,

    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes for resource queries
CREATE INDEX IF NOT EXISTS idx_resources_provider ON resources(provider);
CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(resource_type, available);

-- Resource usage table - tracks consumption
CREATE TABLE IF NOT EXISTS resource_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL,            -- Type of resource
    resource_spec TEXT NOT NULL,            -- JSON spec
    consumer TEXT NOT NULL,                 -- Consumer DID
    provider TEXT NOT NULL,                 -- Provider DID
    started_at INTEGER NOT NULL,            -- Unix timestamp
    ended_at INTEGER,                       -- Unix timestamp (NULL if ongoing)
    units_consumed INTEGER NOT NULL DEFAULT 0,
    cost_millitokens INTEGER NOT NULL DEFAULT 0,

    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes for usage tracking
CREATE INDEX IF NOT EXISTS idx_usage_consumer ON resource_usage(consumer, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_provider ON resource_usage(provider, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_active ON resource_usage(ended_at) WHERE ended_at IS NULL;
