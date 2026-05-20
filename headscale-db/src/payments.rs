//! Payment and ledger persistence operations.

use crate::{
    DbError, Result,
    models::{AccountBalanceRow, TransactionRow},
};
use headscale_payments::ledger::{Transaction, TransactionType};
use sqlx::SqlitePool;

/// Insert a transaction.
pub async fn insert_transaction(pool: &SqlitePool, tx: &Transaction) -> Result<()> {
    let tx_type = match tx.tx_type {
        TransactionType::Transfer => "transfer",
        TransactionType::Deposit => "deposit",
        TransactionType::Withdrawal => "withdrawal",
        TransactionType::ResourcePayment => "resource_payment",
        TransactionType::BountyPayment => "bounty_payment",
        TransactionType::CreditExtension => "credit_extension",
    };

    sqlx::query(
        r#"
        INSERT INTO transactions (
            id, from_account, to_account, amount, description, tx_type, timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&tx.id)
    .bind(&tx.from)
    .bind(&tx.to)
    .bind(tx.amount as i64)
    .bind(&tx.description)
    .bind(tx_type)
    .bind(tx.timestamp as i64)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get transaction history for an account.
pub async fn get_transaction_history(
    pool: &SqlitePool,
    account: &str,
    limit: Option<i64>,
) -> Result<Vec<Transaction>> {
    let limit = limit.unwrap_or(100);

    let rows = sqlx::query_as::<_, TransactionRow>(
        r#"
        SELECT id, from_account, to_account, amount, description, tx_type, timestamp, created_at
        FROM transactions
        WHERE from_account = ? OR to_account = ?
        ORDER BY timestamp DESC
        LIMIT ?
        "#,
    )
    .bind(account)
    .bind(account)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(|row| row.to_transaction()).collect())
}

/// Get all transactions (admin use).
pub async fn get_all_transactions(
    pool: &SqlitePool,
    limit: Option<i64>,
) -> Result<Vec<Transaction>> {
    let limit = limit.unwrap_or(100);

    let rows = sqlx::query_as::<_, TransactionRow>(
        r#"
        SELECT id, from_account, to_account, amount, description, tx_type, timestamp, created_at
        FROM transactions
        ORDER BY timestamp DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(|row| row.to_transaction()).collect())
}

/// Get account balance.
pub async fn get_balance(pool: &SqlitePool, account: &str) -> Result<i64> {
    let row = sqlx::query_as::<_, AccountBalanceRow>(
        r#"
        SELECT account, balance, credit_limit, updated_at
        FROM account_balances
        WHERE account = ?
        "#,
    )
    .bind(account)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.balance).unwrap_or(0))
}

/// Get account available balance (balance + credit limit).
pub async fn get_available_balance(pool: &SqlitePool, account: &str) -> Result<i64> {
    let row = sqlx::query_as::<_, AccountBalanceRow>(
        r#"
        SELECT account, balance, credit_limit, updated_at
        FROM account_balances
        WHERE account = ?
        "#,
    )
    .bind(account)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.balance + r.credit_limit).unwrap_or(0))
}

/// Update account balance.
pub async fn update_balance(pool: &SqlitePool, account: &str, delta: i64) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO account_balances (account, balance, updated_at)
        VALUES (?, ?, unixepoch())
        ON CONFLICT(account) DO UPDATE SET
            balance = balance + ?,
            updated_at = unixepoch()
        "#,
    )
    .bind(account)
    .bind(delta)
    .bind(delta)
    .execute(pool)
    .await?;

    Ok(())
}

/// Set credit limit for an account.
pub async fn set_credit_limit(pool: &SqlitePool, account: &str, limit: i64) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO account_balances (account, credit_limit, updated_at)
        VALUES (?, ?, unixepoch())
        ON CONFLICT(account) DO UPDATE SET
            credit_limit = ?,
            updated_at = unixepoch()
        "#,
    )
    .bind(account)
    .bind(limit)
    .bind(limit)
    .execute(pool)
    .await?;

    Ok(())
}

/// Execute a transfer between accounts (atomic operation).
pub async fn transfer(
    pool: &SqlitePool,
    from: &str,
    to: &str,
    amount: u64,
    description: &str,
) -> Result<Transaction> {
    let mut tx_db = pool.begin().await?;

    // Check available balance
    let available = get_available_balance(pool, from).await?;
    if available < amount as i64 {
        return Err(DbError::Constraint(format!(
            "Insufficient funds: available {} < required {}",
            available, amount
        )));
    }

    // Update balances
    sqlx::query(
        r#"
        INSERT INTO account_balances (account, balance, updated_at)
        VALUES (?, ?, unixepoch())
        ON CONFLICT(account) DO UPDATE SET
            balance = balance - ?,
            updated_at = unixepoch()
        "#,
    )
    .bind(from)
    .bind(-(amount as i64))
    .bind(amount as i64)
    .execute(&mut *tx_db)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO account_balances (account, balance, updated_at)
        VALUES (?, ?, unixepoch())
        ON CONFLICT(account) DO UPDATE SET
            balance = balance + ?,
            updated_at = unixepoch()
        "#,
    )
    .bind(to)
    .bind(amount as i64)
    .bind(amount as i64)
    .execute(&mut *tx_db)
    .await?;

    // Create transaction record
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tx_id = format!("tx_{}", now);

    let transaction = Transaction {
        id: tx_id.clone(),
        from: from.to_string(),
        to: to.to_string(),
        amount,
        description: description.to_string(),
        timestamp: now,
        tx_type: TransactionType::Transfer,
    };

    sqlx::query(
        r#"
        INSERT INTO transactions (
            id, from_account, to_account, amount, description, tx_type, timestamp
        )
        VALUES (?, ?, ?, ?, ?, 'transfer', ?)
        "#,
    )
    .bind(&tx_id)
    .bind(from)
    .bind(to)
    .bind(amount as i64)
    .bind(description)
    .bind(now as i64)
    .execute(&mut *tx_db)
    .await?;

    tx_db.commit().await?;

    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    #[tokio::test]
    async fn test_payment_operations() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let account1 = "did:example:alice";
        let account2 = "did:example:bob";

        // Set initial balances
        update_balance(db.pool(), account1, 1000).await.unwrap();
        update_balance(db.pool(), account2, 500).await.unwrap();

        // Check balances
        let balance1 = get_balance(db.pool(), account1).await.unwrap();
        assert_eq!(balance1, 1000);

        // Transfer
        let tx = transfer(db.pool(), account1, account2, 100, "Test transfer")
            .await
            .unwrap();

        // Check updated balances
        let balance1 = get_balance(db.pool(), account1).await.unwrap();
        let balance2 = get_balance(db.pool(), account2).await.unwrap();
        assert_eq!(balance1, 900);
        assert_eq!(balance2, 600);

        // Check transaction history
        let history = get_transaction_history(db.pool(), account1, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].amount, 100);

        // Test credit limit
        set_credit_limit(db.pool(), account1, 500).await.unwrap();
        let available = get_available_balance(db.pool(), account1).await.unwrap();
        assert_eq!(available, 1400); // 900 balance + 500 credit

        // Test insufficient funds
        let result = transfer(db.pool(), account1, account2, 2000, "Should fail").await;
        assert!(result.is_err());
    }
}
