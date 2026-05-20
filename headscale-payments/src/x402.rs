//! x402 HTTP micropayment handler.

use std::sync::Arc;

use crate::ledger::Ledger;

/// Handles x402 HTTP micropayments.
pub struct X402Handler {
    ledger: Arc<Ledger>,
}

/// An x402 payment request.
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// Resource being accessed
    pub resource: String,
    /// Price in millitokens
    pub price: u64,
    /// Payment recipient
    pub recipient: String,
    /// Expiry timestamp
    pub expires_at: u64,
    /// Payment nonce
    pub nonce: String,
}

/// An x402 payment proof.
#[derive(Debug, Clone)]
pub struct PaymentProof {
    /// Request nonce
    pub nonce: String,
    /// Payer DID
    pub payer: String,
    /// Signature
    pub signature: Vec<u8>,
    /// Transaction ID from ledger
    pub tx_id: Option<String>,
}

impl X402Handler {
    pub fn new(ledger: Arc<Ledger>) -> Self {
        Self { ledger }
    }

    /// Create a payment request for a resource.
    pub fn create_request(
        &self,
        resource: &str,
        price: u64,
        recipient: &str,
        ttl_secs: u64,
    ) -> PaymentRequest {
        PaymentRequest {
            resource: resource.to_string(),
            price,
            recipient: recipient.to_string(),
            expires_at: now() + ttl_secs,
            nonce: generate_nonce(),
        }
    }

    /// Verify a payment proof and process the payment.
    pub async fn verify_and_pay(
        &self,
        request: &PaymentRequest,
        proof: &PaymentProof,
    ) -> Result<String, X402Error> {
        // Check expiry
        if now() > request.expires_at {
            return Err(X402Error::Expired);
        }

        // Check nonce matches
        if proof.nonce != request.nonce {
            return Err(X402Error::InvalidNonce);
        }

        // Verify signature (simplified - would use ed25519 in production)
        if proof.signature.is_empty() {
            return Err(X402Error::InvalidSignature);
        }

        // Process payment
        let tx = self
            .ledger
            .pay_for_resource(
                &proof.payer,
                &request.recipient,
                request.price,
                &format!("x402 payment for {}", request.resource),
            )
            .await
            .map_err(|_| X402Error::PaymentFailed)?;

        Ok(tx.id)
    }

    /// Generate x402 response headers.
    pub fn response_headers(request: &PaymentRequest) -> Vec<(String, String)> {
        vec![
            ("X-Payment-Required".to_string(), "true".to_string()),
            ("X-Payment-Price".to_string(), request.price.to_string()),
            ("X-Payment-Recipient".to_string(), request.recipient.clone()),
            (
                "X-Payment-Expires".to_string(),
                request.expires_at.to_string(),
            ),
            ("X-Payment-Nonce".to_string(), request.nonce.clone()),
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum X402Error {
    #[error("Payment request expired")]
    Expired,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Payment failed")]
    PaymentFailed,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_nonce() -> String {
    format!("nonce_{}", now())
}
