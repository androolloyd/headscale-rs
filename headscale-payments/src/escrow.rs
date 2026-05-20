//! Escrow for work bounties.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::ledger::Ledger;

/// Escrow manager for work bounties.
pub struct Escrow {
    ledger: Arc<Ledger>,
    /// Active escrows
    escrows: Arc<RwLock<HashMap<String, EscrowRecord>>>,
}

/// An escrow record.
#[derive(Debug, Clone)]
pub struct EscrowRecord {
    pub id: String,
    pub work_id: String,
    pub funder: String,
    pub recipients: Vec<(String, u8)>, // (DID, share percentage)
    pub total: u64,
    pub released: u64,
    pub state: EscrowState,
    pub created_at: u64,
    pub milestones: Vec<Milestone>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscrowState {
    Funded,
    Active,
    PendingVerification,
    Released,
    Disputed,
    Refunded,
}

#[derive(Debug, Clone)]
pub struct Milestone {
    pub description: String,
    pub percentage: u8,
    pub completed: bool,
    pub verified_by: Option<String>,
}

impl Escrow {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self {
            ledger,
            escrows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new escrow for work.
    pub async fn create(
        &self,
        work_id: &str,
        funder: &str,
        recipients: Vec<(String, u8)>,
        total: u64,
        milestones: Vec<Milestone>,
    ) -> Result<String, EscrowError> {
        // Verify recipient shares sum to 100
        let total_shares: u8 = recipients.iter().map(|(_, s)| s).sum();
        if total_shares != 100 {
            return Err(EscrowError::InvalidShares);
        }

        // Verify milestone percentages sum to 100
        let total_milestone: u8 = milestones.iter().map(|m| m.percentage).sum();
        if total_milestone != 100 {
            return Err(EscrowError::InvalidMilestones);
        }

        // Transfer funds to escrow account
        let escrow_id = generate_escrow_id();
        let escrow_account = format!("escrow:{escrow_id}");

        self.ledger
            .transfer(
                funder,
                &escrow_account,
                total,
                &format!("Escrow for work {work_id}"),
            )
            .await
            .map_err(|_| EscrowError::InsufficientFunds)?;

        let record = EscrowRecord {
            id: escrow_id.clone(),
            work_id: work_id.to_string(),
            funder: funder.to_string(),
            recipients,
            total,
            released: 0,
            state: EscrowState::Funded,
            created_at: now(),
            milestones,
        };

        self.escrows.write().await.insert(escrow_id.clone(), record);
        Ok(escrow_id)
    }

    /// Release a milestone.
    pub async fn release_milestone(
        &self,
        escrow_id: &str,
        milestone_index: usize,
        verifier: &str,
    ) -> Result<u64, EscrowError> {
        let mut escrows = self.escrows.write().await;
        let record = escrows.get_mut(escrow_id).ok_or(EscrowError::NotFound)?;

        if record.state == EscrowState::Released || record.state == EscrowState::Refunded {
            return Err(EscrowError::AlreadyClosed);
        }

        let milestone = record
            .milestones
            .get_mut(milestone_index)
            .ok_or(EscrowError::InvalidMilestone)?;

        if milestone.completed {
            return Err(EscrowError::MilestoneAlreadyReleased);
        }

        milestone.completed = true;
        milestone.verified_by = Some(verifier.to_string());

        let amount = (record.total * milestone.percentage as u64) / 100;
        record.released += amount;
        record.state = EscrowState::Active;

        // Distribute to recipients
        let escrow_account = format!("escrow:{escrow_id}");
        for (recipient, share) in &record.recipients {
            let recipient_amount = (amount * *share as u64) / 100;
            self.ledger
                .transfer(
                    &escrow_account,
                    recipient,
                    recipient_amount,
                    &format!(
                        "Milestone {} release for work {}",
                        milestone_index, record.work_id
                    ),
                )
                .await
                .map_err(|_| EscrowError::TransferFailed)?;
        }

        if record.released >= record.total {
            record.state = EscrowState::Released;
        }

        Ok(amount)
    }

    /// Release all remaining funds.
    pub async fn release_all(&self, escrow_id: &str, verifier: &str) -> Result<u64, EscrowError> {
        let mut escrows = self.escrows.write().await;
        let record = escrows.get_mut(escrow_id).ok_or(EscrowError::NotFound)?;

        if record.state == EscrowState::Released || record.state == EscrowState::Refunded {
            return Err(EscrowError::AlreadyClosed);
        }

        let remaining = record.total - record.released;
        record.released = record.total;
        record.state = EscrowState::Released;

        // Mark all milestones as completed
        for milestone in &mut record.milestones {
            if !milestone.completed {
                milestone.completed = true;
                milestone.verified_by = Some(verifier.to_string());
            }
        }

        // Distribute to recipients
        let escrow_account = format!("escrow:{escrow_id}");
        for (recipient, share) in &record.recipients {
            let recipient_amount = (remaining * *share as u64) / 100;
            self.ledger
                .transfer(
                    &escrow_account,
                    recipient,
                    recipient_amount,
                    &format!("Final release for work {}", record.work_id),
                )
                .await
                .map_err(|_| EscrowError::TransferFailed)?;
        }

        Ok(remaining)
    }

    /// Refund escrow to funder.
    pub async fn refund(&self, escrow_id: &str) -> Result<u64, EscrowError> {
        let mut escrows = self.escrows.write().await;
        let record = escrows.get_mut(escrow_id).ok_or(EscrowError::NotFound)?;

        if record.state == EscrowState::Released {
            return Err(EscrowError::AlreadyClosed);
        }

        let remaining = record.total - record.released;
        record.state = EscrowState::Refunded;

        // Return to funder
        let escrow_account = format!("escrow:{escrow_id}");
        self.ledger
            .transfer(
                &escrow_account,
                &record.funder,
                remaining,
                &format!("Refund for work {}", record.work_id),
            )
            .await
            .map_err(|_| EscrowError::TransferFailed)?;

        Ok(remaining)
    }

    /// Get escrow status.
    pub async fn status(&self, escrow_id: &str) -> Option<EscrowRecord> {
        self.escrows.read().await.get(escrow_id).cloned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("Escrow not found")]
    NotFound,
    #[error("Escrow already closed")]
    AlreadyClosed,
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Invalid recipient shares (must sum to 100)")]
    InvalidShares,
    #[error("Invalid milestones (must sum to 100)")]
    InvalidMilestones,
    #[error("Invalid milestone index")]
    InvalidMilestone,
    #[error("Milestone already released")]
    MilestoneAlreadyReleased,
    #[error("Transfer failed")]
    TransferFailed,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_escrow_id() -> String {
    format!("escrow_{}", now())
}
