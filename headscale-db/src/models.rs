//! Database models and conversions.

use std::net::IpAddr;

/// Database model for a node.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeRow {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub addresses: String, // JSON
    pub endpoints: String, // JSON
    pub last_seen: i64,
    pub online: bool,
    pub cap_relay: bool,
    pub cap_inference: bool,
    pub cap_storage: bool,
    pub cap_compute: bool,
    pub cap_seed: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl NodeRow {
    /// Convert to headscale_core::node::Node
    pub fn to_node(&self) -> Result<headscale_core::node::Node, crate::DbError> {
        let addresses: Vec<IpAddr> = serde_json::from_str(&self.addresses)?;
        let endpoints: Vec<String> = serde_json::from_str(&self.endpoints)?;

        Ok(headscale_core::node::Node {
            id: self.id.clone(),
            name: self.name.clone(),
            wg_pubkey: self.wg_pubkey.clone(),
            addresses,
            endpoints,
            last_seen: self.last_seen as u64,
            online: self.online,
            capabilities: headscale_core::node::NodeCapabilities {
                relay: self.cap_relay,
                inference: self.cap_inference,
                storage: self.cap_storage,
                compute: self.cap_compute,
                seed: self.cap_seed,
            },
        })
    }
}

/// Database model for a transaction.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransactionRow {
    pub id: String,
    pub from_account: String,
    pub to_account: String,
    pub amount: i64,
    pub description: String,
    pub tx_type: String,
    pub timestamp: i64,
    pub created_at: i64,
}

impl TransactionRow {
    /// Convert to headscale_payments::ledger::Transaction
    pub fn to_transaction(&self) -> headscale_payments::ledger::Transaction {
        use headscale_payments::ledger::TransactionType;

        let tx_type = match self.tx_type.as_str() {
            "deposit" => TransactionType::Deposit,
            "withdrawal" => TransactionType::Withdrawal,
            "resource_payment" => TransactionType::ResourcePayment,
            "bounty_payment" => TransactionType::BountyPayment,
            "credit_extension" => TransactionType::CreditExtension,
            // "transfer" + unknown both fall through to Transfer (default).
            _ => TransactionType::Transfer,
        };

        headscale_payments::ledger::Transaction {
            id: self.id.clone(),
            from: self.from_account.clone(),
            to: self.to_account.clone(),
            amount: self.amount as u64,
            description: self.description.clone(),
            timestamp: self.timestamp as u64,
            tx_type,
        }
    }
}

/// Database model for account balance.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountBalanceRow {
    pub account: String,
    pub balance: i64,
    pub credit_limit: i64,
    pub updated_at: i64,
}

/// Database model for a resource.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceRow {
    pub id: i64,
    pub provider: String,
    pub resource_type: String,
    pub resource_spec: String, // JSON
    pub pricing: String,       // JSON
    pub available: bool,
    pub last_updated: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ResourceRow {
    /// Convert to headscale_resources::registry::ProviderResource
    pub fn to_provider_resource(
        &self,
    ) -> Result<headscale_resources::registry::ProviderResource, crate::DbError> {
        let resource_type: headscale_resources::types::ResourceType =
            serde_json::from_str(&self.resource_spec)?;
        let pricing: headscale_resources::types::ResourcePricing =
            serde_json::from_str(&self.pricing)?;

        Ok(headscale_resources::registry::ProviderResource {
            provider: self.provider.clone(),
            resource_type,
            pricing,
            available: self.available,
            last_updated: self.last_updated as u64,
        })
    }
}

/// Database model for resource usage.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceUsageRow {
    pub id: i64,
    pub resource_type: String,
    pub resource_spec: String, // JSON
    pub consumer: String,
    pub provider: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub units_consumed: i64,
    pub cost_millitokens: i64,
    pub created_at: i64,
}

impl ResourceUsageRow {
    /// Convert to headscale_resources::types::ResourceUsage
    pub fn to_resource_usage(
        &self,
    ) -> Result<headscale_resources::types::ResourceUsage, crate::DbError> {
        let resource_type: headscale_resources::types::ResourceType =
            serde_json::from_str(&self.resource_spec)?;

        Ok(headscale_resources::types::ResourceUsage {
            resource_type,
            consumer: self.consumer.clone(),
            provider: self.provider.clone(),
            started_at: self.started_at as u64,
            ended_at: self.ended_at.map(|t| t as u64),
            units_consumed: self.units_consumed as u64,
            cost_millitokens: self.cost_millitokens as u64,
        })
    }
}

/// Database model for a session.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SessionRow {
    pub token: String,
    pub did: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub capabilities: String, // JSON
}

impl SessionRow {
    /// Convert to headscale_identity::session::Session
    pub fn to_session(&self) -> Result<headscale_identity::session::Session, crate::DbError> {
        use headscale_identity::did::Did;

        let capabilities: Vec<String> = serde_json::from_str(&self.capabilities)?;
        let did = Did::parse(&self.did)
            .map_err(|e| crate::DbError::General(format!("Invalid DID: {e}")))?;

        Ok(headscale_identity::session::Session {
            did,
            token: self.token.clone(),
            created_at: self.created_at as u64,
            expires_at: self.expires_at as u64,
            capabilities,
        })
    }
}
