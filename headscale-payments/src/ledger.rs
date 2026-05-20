//! Internal ledger for fast settlement.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Internal ledger for tracking balances.
pub struct Ledger {
    /// Account balances (DID → balance in millitokens)
    balances: Arc<RwLock<HashMap<String, i64>>>,
    /// Credit limits (DID → max credit)
    credit_limits: Arc<RwLock<HashMap<String, u64>>>,
    /// Transaction history
    transactions: Arc<RwLock<Vec<Transaction>>>,
}

/// A ledger transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub id: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub description: String,
    pub timestamp: u64,
    pub tx_type: TransactionType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionType {
    /// Direct transfer between accounts
    Transfer,
    /// Deposit from external source
    Deposit,
    /// Withdrawal to external destination
    Withdrawal,
    /// Resource payment
    ResourcePayment,
    /// Work bounty payment
    BountyPayment,
    /// Credit extension
    CreditExtension,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            balances: Arc::new(RwLock::new(HashMap::new())),
            credit_limits: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get account balance.
    pub async fn balance(&self, account: &str) -> i64 {
        *self.balances.read().await.get(account).unwrap_or(&0)
    }

    /// Get available balance (balance + credit limit).
    pub async fn available(&self, account: &str) -> i64 {
        let balance = self.balance(account).await;
        let credit = *self.credit_limits.read().await.get(account).unwrap_or(&0) as i64;

        balance + credit
    }

    /// Deposit funds to an account.
    pub async fn deposit(&self, account: &str, amount: u64, description: &str) -> Transaction {
        let mut balances = self.balances.write().await;
        *balances.entry(account.to_string()).or_insert(0) += amount as i64;

        let tx = Transaction {
            id: generate_tx_id(),
            from: "external".to_string(),
            to: account.to_string(),
            amount,
            description: description.to_string(),
            timestamp: now(),
            tx_type: TransactionType::Deposit,
        };

        self.transactions.write().await.push(tx.clone());
        tx
    }

    /// Transfer between accounts.
    pub async fn transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        description: &str,
    ) -> Result<Transaction, LedgerError> {
        // Check available balance
        if self.available(from).await < amount as i64 {
            return Err(LedgerError::InsufficientFunds);
        }

        let mut balances = self.balances.write().await;
        *balances.entry(from.to_string()).or_insert(0) -= amount as i64;
        *balances.entry(to.to_string()).or_insert(0) += amount as i64;

        let tx = Transaction {
            id: generate_tx_id(),
            from: from.to_string(),
            to: to.to_string(),
            amount,
            description: description.to_string(),
            timestamp: now(),
            tx_type: TransactionType::Transfer,
        };

        drop(balances);
        self.transactions.write().await.push(tx.clone());
        Ok(tx)
    }

    /// Pay for resource usage.
    pub async fn pay_for_resource(
        &self,
        consumer: &str,
        provider: &str,
        amount: u64,
        resource_description: &str,
    ) -> Result<Transaction, LedgerError> {
        // Check available balance
        if self.available(consumer).await < amount as i64 {
            return Err(LedgerError::InsufficientFunds);
        }

        let mut balances = self.balances.write().await;
        *balances.entry(consumer.to_string()).or_insert(0) -= amount as i64;
        *balances.entry(provider.to_string()).or_insert(0) += amount as i64;

        let tx = Transaction {
            id: generate_tx_id(),
            from: consumer.to_string(),
            to: provider.to_string(),
            amount,
            description: resource_description.to_string(),
            timestamp: now(),
            tx_type: TransactionType::ResourcePayment,
        };

        drop(balances);
        self.transactions.write().await.push(tx.clone());
        Ok(tx)
    }

    /// Set credit limit for an account.
    pub async fn set_credit_limit(&self, account: &str, limit: u64) {
        self.credit_limits
            .write()
            .await
            .insert(account.to_string(), limit);
    }

    /// Get transaction history for an account.
    pub async fn history(&self, account: &str) -> Vec<Transaction> {
        self.transactions
            .read()
            .await
            .iter()
            .filter(|tx| tx.from == account || tx.to == account)
            .cloned()
            .collect()
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Account not found")]
    AccountNotFound,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_tx_id() -> String {
    format!("tx_{}", now())
}
