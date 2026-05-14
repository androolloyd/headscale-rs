# headscale-db

SQLite persistence layer for headscale-rs.

## Overview

This crate provides database persistence for:
- **Nodes**: Mesh network nodes with capabilities
- **Transactions**: Payment ledger transactions and balances
- **Resources**: Available resources and usage tracking
- **Sessions**: Authenticated user sessions

## Database Schema

### Nodes Table
Stores registered mesh nodes with their capabilities and status.

```sql
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,              -- Node DID
    name TEXT NOT NULL,               -- Human-readable name
    wg_pubkey TEXT NOT NULL UNIQUE,   -- WireGuard public key
    addresses TEXT NOT NULL,          -- JSON array of IP addresses
    endpoints TEXT NOT NULL,          -- JSON array of endpoints
    last_seen INTEGER NOT NULL,       -- Unix timestamp
    online BOOLEAN NOT NULL,          -- Online status
    cap_relay BOOLEAN NOT NULL,       -- Can route traffic
    cap_inference BOOLEAN NOT NULL,   -- Provides LLM inference
    cap_storage BOOLEAN NOT NULL,     -- Provides storage
    cap_compute BOOLEAN NOT NULL,     -- Provides compute
    cap_seed BOOLEAN NOT NULL,        -- Is a seed node
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### Transactions Table
Stores all ledger transactions.

```sql
CREATE TABLE transactions (
    id TEXT PRIMARY KEY,
    from_account TEXT NOT NULL,
    to_account TEXT NOT NULL,
    amount INTEGER NOT NULL,          -- millitokens
    description TEXT NOT NULL,
    tx_type TEXT NOT NULL,            -- transfer, deposit, withdrawal, etc.
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

### Account Balances Table
Stores current account balances and credit limits.

```sql
CREATE TABLE account_balances (
    account TEXT PRIMARY KEY,         -- DID
    balance INTEGER NOT NULL,         -- Current balance in millitokens
    credit_limit INTEGER NOT NULL,    -- Credit limit in millitokens
    updated_at INTEGER NOT NULL
);
```

### Resources Table
Tracks available resources from providers.

```sql
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,      -- inference, storage, compute, bandwidth
    resource_spec TEXT NOT NULL,      -- JSON spec
    pricing TEXT NOT NULL,            -- JSON pricing
    available BOOLEAN NOT NULL,
    last_updated INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### Resource Usage Table
Tracks resource consumption.

```sql
CREATE TABLE resource_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_type TEXT NOT NULL,
    resource_spec TEXT NOT NULL,      -- JSON spec
    consumer TEXT NOT NULL,           -- Consumer DID
    provider TEXT NOT NULL,           -- Provider DID
    started_at INTEGER NOT NULL,
    ended_at INTEGER,                 -- NULL if ongoing
    units_consumed INTEGER NOT NULL,
    cost_millitokens INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
```

### Sessions Table
Stores authenticated sessions.

```sql
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    capabilities TEXT NOT NULL,       -- JSON array
    FOREIGN KEY (did) REFERENCES nodes(id) ON DELETE CASCADE
);
```

## Usage

```rust
use headscale_db::Database;

// Create database connection
let db = Database::new("sqlite://headscale.db").await?;

// Run migrations
db.migrate().await?;

// Use the connection pool
let pool = db.pool();

// Insert a node
headscale_db::nodes::upsert_node(pool, &node).await?;

// Get a node
let node = headscale_db::nodes::get_node(pool, "did:example:123").await?;

// Transfer funds
let tx = headscale_db::payments::transfer(
    pool,
    "did:alice",
    "did:bob",
    100,
    "Payment for services"
).await?;
```

## Running Migrations

Migrations are located in `migrations/` and are automatically applied when calling `db.migrate()`.

## Setting Up for Development

To use compile-time query checking with sqlx macros:

1. Install sqlx-cli:
   ```bash
   cargo install sqlx-cli --no-default-features --features sqlite
   ```

2. Create a test database:
   ```bash
   cd headscale-db
   sqlite3 headscale.db < migrations/20260118000001_create_nodes.sql
   sqlite3 headscale.db < migrations/20260118000002_create_transactions.sql
   sqlite3 headscale.db < migrations/20260118000003_create_resources.sql
   sqlite3 headscale.db < migrations/20260118000004_create_sessions.sql
   ```

3. Prepare offline query data:
   ```bash
   cargo sqlx prepare --package headscale-db
   ```

## Testing

```bash
cargo test --package headscale-db
```

Tests use in-memory SQLite databases and don't require external setup.

## Features

- **Connection pooling**: Automatic connection management with configurable pool size
- **Migrations**: Built-in migration support using sqlx
- **Atomic transactions**: Database transactions for consistency
- **Indexes**: Optimized queries with appropriate indexes
- **JSON storage**: Flexible storage of complex types
- **Type safety**: Strong typing with Rust structs

## Performance

- Connection pool size: 10 connections (configurable)
- Idle timeout: 300 seconds
- Uses prepared statements for all queries
- Indexes on frequently queried columns

## Future Enhancements

- [ ] Add database backup/restore functionality
- [ ] Implement database compaction
- [ ] Add query performance metrics
- [ ] Support for PostgreSQL backend
- [ ] Add database migration rollback support
