#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use headscale_core::accounting::{AccountingPipeline, ResourceKind, Pricing};
use std::time::Duration;

/// Arbitrary pricing configuration.
#[derive(Debug, Arbitrary)]
struct FuzzPricing {
    rate_per_unit: u64,
    minimum_units: u64,
    settlement_interval_secs: u64,
}

impl FuzzPricing {
    fn to_pricing(&self) -> Pricing {
        Pricing {
            // Bound rate to reasonable values
            rate_per_unit: self.rate_per_unit.max(1).min(1_000_000),
            minimum_units: self.minimum_units.max(1).min(1_000),
            settlement_interval_secs: self.settlement_interval_secs.max(1).min(3600),
        }
    }
}

/// Arbitrary escrow creation parameters.
#[derive(Debug, Arbitrary)]
struct FuzzEscrow {
    consumer: String,
    provider: String,
    amount: u64,
    resource_kind: u8,
    pricing: FuzzPricing,
    has_duration: bool,
    duration_secs: u64,
}

/// Arbitrary session operation.
#[derive(Debug, Arbitrary)]
enum FuzzOperation {
    /// Record usage units
    RecordUsage { units: u64 },
    /// Settle session (non-final)
    Settle,
    /// End session (final settlement)
    End,
}

/// Combined input for fuzzing.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    escrow: FuzzEscrow,
    operations: Vec<FuzzOperation>,
}

fuzz_target!(|input: FuzzInput| {
    // Create runtime for async operations
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let pipeline = AccountingPipeline::new();

        // Create escrow with bounded values
        let resource_kind = match input.escrow.resource_kind % 4 {
            0 => ResourceKind::Bandwidth,
            1 => ResourceKind::Inference,
            2 => ResourceKind::Storage,
            _ => ResourceKind::Compute,
        };

        let duration = if input.escrow.has_duration {
            Some(Duration::from_secs(input.escrow.duration_secs.max(1).min(86400)))
        } else {
            None
        };

        // Bound escrow amount to prevent overflow issues
        let amount = input.escrow.amount.max(1).min(1_000_000_000);

        let escrow_id = pipeline.create_escrow(
            input.escrow.consumer.clone(),
            input.escrow.provider.clone(),
            amount,
            resource_kind,
            input.escrow.pricing.to_pricing(),
            duration,
        ).await;

        // Verify escrow created
        let escrow = pipeline.get_escrow(&escrow_id).await;
        assert!(escrow.is_some(), "Escrow should be created");
        let escrow = escrow.unwrap();
        assert_eq!(escrow.deposited, amount);
        assert!(escrow.active);

        // Try to start session
        let session_result = pipeline.start_session(&escrow_id).await;

        if let Ok(session_id) = session_result {
            let mut session_ended = false;

            // Execute operations
            for op in &input.operations {
                if session_ended {
                    break;
                }

                match op {
                    FuzzOperation::RecordUsage { units } => {
                        // Bound units to prevent overflow
                        let bounded_units = (*units).min(1_000_000);
                        let _ = pipeline.record_usage(&session_id, bounded_units).await;
                    }
                    FuzzOperation::Settle => {
                        let _ = pipeline.settle_session(&session_id, false).await;
                    }
                    FuzzOperation::End => {
                        let _ = pipeline.end_session(&session_id).await;
                        session_ended = true;
                    }
                }
            }

            // Clean up if session still active
            if !session_ended {
                let _ = pipeline.end_session(&session_id).await;
            }

            // Verify accounting consistency
            let final_escrow = pipeline.get_escrow(&escrow_id).await.unwrap();

            // Spent + remaining should equal deposited (minus any reserved)
            assert!(
                final_escrow.spent + final_escrow.remaining + final_escrow.reserved <= final_escrow.deposited,
                "Accounting invariant violated: spent({}) + remaining({}) + reserved({}) > deposited({})",
                final_escrow.spent,
                final_escrow.remaining,
                final_escrow.reserved,
                final_escrow.deposited
            );
        }

        // Test closing escrow
        let close_result = pipeline.close_escrow(&escrow_id).await;
        assert!(close_result.is_ok(), "Should be able to close escrow");

        let closed = close_result.unwrap();
        assert!(!closed.active, "Closed escrow should be inactive");

        // Cannot start session on closed escrow
        let session_result = pipeline.start_session(&escrow_id).await;
        assert!(session_result.is_err(), "Cannot start session on closed escrow");
    });
});
