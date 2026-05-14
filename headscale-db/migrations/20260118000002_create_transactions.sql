-- Transactions table - stores ledger transactions
CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,                    -- Transaction ID
    from_account TEXT NOT NULL,             -- Sender DID or "external"
    to_account TEXT NOT NULL,               -- Receiver DID
    amount INTEGER NOT NULL,                -- Amount in millitokens
    description TEXT NOT NULL,              -- Transaction description
    tx_type TEXT NOT NULL,                  -- transfer, deposit, withdrawal, resource_payment, bounty_payment, credit_extension
    timestamp INTEGER NOT NULL,             -- Unix timestamp

    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes for transaction queries
CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_account, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_account, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(tx_type);

-- Account balances table - stores current balances
CREATE TABLE IF NOT EXISTS account_balances (
    account TEXT PRIMARY KEY,               -- DID
    balance INTEGER NOT NULL DEFAULT 0,     -- Current balance in millitokens
    credit_limit INTEGER NOT NULL DEFAULT 0, -- Credit limit in millitokens
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
