# SQLite Persistence Implementation

## Summary

Implemented a comprehensive SQLite persistence layer for headscale-rs with the following components:

## 1. Database Schema Design

Created four migration files with comprehensive schemas:

### Migration 20260118000001 - Nodes Table
- Stores mesh network nodes with DID-based identity
- Tracks WireGuard configuration (public key, endpoints)
- Stores IP address allocations (JSON array)
- Five capability flags: relay, inference, storage, compute, seed
- Indexes on public key, capabilities, and online status

### Migration 20260118000002 - Transactions & Balances
- **Transactions table**: Complete ledger history with support for 6 transaction types
- **Account balances table**: Current balance and credit limit per account
- Indexes optimized for history queries (by account, timestamp, type)

### Migration 20260118000003 - Resources
- **Resources table**: Available resources from providers with JSON specs
- **Resource usage table**: Consumption tracking with start/end timestamps
- Supports four resource types: inference, storage, compute, bandwidth
- Indexes for provider/consumer queries and active usage tracking

### Migration 20260118000004 - Sessions
- Session management with token-based authentication
- Automatic cleanup trigger for expired sessions
- Foreign key relationship to nodes table
- Capabilities stored as JSON array

## 2. Core Database Module (`src/lib.rs`)

- `Database` struct with connection pooling (10 max connections)
- Configurable idle timeout (300 seconds)
- Built-in migration support via `db.migrate()`
- In-memory database support for testing
- Clean shutdown with `db.close()`

## 3. Error Handling (`src/error.rs`)

Comprehensive error types:
- `DbError::Sqlx` - Database errors
- `DbError::Migration` - Migration failures
- `DbError::Serialization` - JSON ser/de errors
- `DbError::NotFound` - Record not found
- `DbError::Constraint` - Constraint violations
- `DbError::General` - General errors

## 4. Data Models (`src/models.rs`)

Type-safe conversion between database rows and domain types:
- `NodeRow` → `headscale_core::node::Node`
- `TransactionRow` → `headscale_payments::ledger::Transaction`
- `AccountBalanceRow` - Balance and credit data
- `ResourceRow` → `headscale_resources::registry::ProviderResource`
- `ResourceUsageRow` → `headscale_resources::types::ResourceUsage`
- `SessionRow` → `headscale_identity::session::Session`

All conversions handle JSON serialization/deserialization transparently.

## 5. Nodes Persistence (`src/nodes.rs`)

Functions implemented:
- `upsert_node()` - Insert or update node (handles conflicts)
- `get_node()` - Fetch node by DID
- `list_nodes()` - Get all nodes sorted by last seen
- `list_nodes_with_capability()` - Filter by capability (relay, inference, etc.)
- `update_heartbeat()` - Update last seen timestamp
- `mark_offline()` - Mark node as offline
- `delete_node()` - Remove node

Includes comprehensive tests for CRUD operations.

## 6. Payments Persistence (`src/payments.rs`)

Functions implemented:
- `insert_transaction()` - Record a transaction
- `get_transaction_history()` - Account history with optional limit
- `get_all_transactions()` - Admin function for all transactions
- `get_balance()` - Current balance
- `get_available_balance()` - Balance + credit limit
- `update_balance()` - Add/subtract from balance
- `set_credit_limit()` - Configure credit limit
- `transfer()` - **Atomic transfer** with balance checks

The `transfer()` function uses database transactions for atomic operations and validates sufficient funds before executing.

Includes tests for balance operations, transfers, and credit limits.

## 7. Resources Persistence (`src/resources.rs`)

Functions implemented:
- `register_resource()` - Register a resource from provider
- `find_providers()` - Find providers by resource type
- `get_provider_resources()` - All resources from a provider
- `mark_resource_unavailable()` - Mark resource as unavailable
- `mark_resource_available()` - Mark resource as available
- `delete_resource()` - Remove resource
- `record_usage()` - Start tracking resource usage
- `complete_usage()` - Finalize usage with units and cost
- `get_consumer_usage()` - Usage history for consumer
- `get_provider_usage()` - Usage history for provider
- `get_active_usage()` - Currently active usage sessions

Helper function `get_resource_type_name()` maps `ResourceType` enum to string.

Includes tests for resource registration, usage tracking, and availability.

## 8. Sessions Persistence (`src/sessions.rs`)

Functions implemented:
- `create_session()` - Create new session
- `get_session()` - Fetch session by token
- `get_sessions_by_did()` - All active sessions for a DID
- `delete_session()` - Delete specific session
- `delete_sessions_by_did()` - Delete all sessions for DID
- `cleanup_expired_sessions()` - Remove expired sessions
- `is_session_valid()` - Check if session exists and not expired

Includes tests for session lifecycle and expiration.

## 9. Configuration Files

- `.env` - Database URL configuration
- `build.rs` - Build script for sqlx offline mode
- `README.md` - Comprehensive documentation

## Key Design Decisions

1. **SQLite over PostgreSQL**: Simpler deployment, no external dependencies
2. **JSON for complex types**: Flexible storage for arrays and nested structures
3. **Unix timestamps**: Consistent time representation
4. **Compile-time query checking**: Using sqlx macros for type safety
5. **Connection pooling**: Efficient resource management
6. **Indexes**: Strategic indexes on frequently queried columns
7. **Atomic operations**: Database transactions for consistency

## Testing Strategy

- In-memory databases for unit tests
- No external dependencies for tests
- Comprehensive CRUD operation coverage
- Tests for atomic operations (transfers)
- Tests for constraints and validation

## Integration Points

The persistence layer integrates with:
- `headscale-core` - Node and mesh management
- `headscale-identity` - DID and session management
- `headscale-resources` - Resource registry and usage
- `headscale-payments` - Ledger and transactions

## Next Steps

To use this persistence layer:

1. Install sqlx-cli:
   ```bash
   cargo install sqlx-cli --no-default-features --features sqlite
   ```

2. Prepare offline query data:
   ```bash
   cd headscale-db
   cargo sqlx prepare
   ```

3. Integrate with existing components:
   - Replace in-memory `Ledger` with database-backed version
   - Replace in-memory `ResourceRegistry` with database-backed version
   - Replace in-memory `MeshCoordinator` with database-backed version

## Performance Characteristics

- Connection pool: 10 connections (configurable)
- Idle timeout: 300 seconds (configurable)
- Query preparation: Compile-time checking via sqlx macros
- Indexes: Optimized for common query patterns
- Transactions: Atomic operations for consistency

## File Structure

```
headscale-db/
├── Cargo.toml
├── README.md
├── IMPLEMENTATION.md
├── build.rs
├── .env
├── migrations/
│   ├── 20260118000001_create_nodes.sql
│   ├── 20260118000002_create_transactions.sql
│   ├── 20260118000003_create_resources.sql
│   └── 20260118000004_create_sessions.sql
└── src/
    ├── lib.rs          # Database connection and setup
    ├── error.rs        # Error types
    ├── models.rs       # Data models and conversions
    ├── nodes.rs        # Node persistence
    ├── payments.rs     # Payment/ledger persistence
    ├── resources.rs    # Resource persistence
    └── sessions.rs     # Session persistence
```

## Status

✅ Schema design complete
✅ Migration files created
✅ Database connection pooling implemented
✅ All persistence modules implemented
✅ Comprehensive tests added
✅ Documentation complete

⏳ Awaiting: sqlx-cli installation for offline query preparation
⏳ Awaiting: Integration with existing in-memory components
