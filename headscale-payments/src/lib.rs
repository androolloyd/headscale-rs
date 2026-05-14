//! Headscale-rs Payments
//!
//! Payment ledger, x402 micropayments, and settlement.
//!
//! This crate handles:
//! - Internal ledger for fast settlement
//! - x402 HTTP micropayment integration
//! - Payment channel management
//! - Escrow and bounty handling
//! - Settlement to external chains

pub mod channels;
pub mod escrow;
pub mod ledger;
pub mod x402;

pub use channels::PaymentChannel;
pub use escrow::Escrow;
pub use ledger::Ledger;
pub use x402::X402Handler;
