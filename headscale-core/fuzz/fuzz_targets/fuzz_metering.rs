#![no_main]

use arbitrary::Arbitrary;
use headscale_core::metering::{
    MeteringConfig, MeteringError, MeteringService, MeteringSessionId, MeteringSnapshot,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum MeteringOp {
    Record { bytes_in: u64, bytes_out: u64 },
    GetUsage,
    ActiveSessions,
    ConsumerSessions,
    ProviderSessions,
    ProviderTotal,
    End,
}

#[derive(Arbitrary, Debug)]
struct MeteringFuzzInput {
    session_id: String,
    consumer_did: String,
    provider_did: String,
    bandwidth_limit: Option<u64>,
    rate_limit: Option<u64>,
    ops: Vec<MeteringOp>,
}

fuzz_target!(|input: MeteringFuzzInput| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(async move {
        let service = MeteringService::new();
        let session_id = MeteringSessionId::new(input.session_id);
        let config = MeteringConfig {
            bandwidth_limit: input.bandwidth_limit,
            rate_limit: input.rate_limit,
            consumer_did: input.consumer_did,
            provider_did: input.provider_did,
        };

        service
            .start_session(session_id.clone(), config.clone())
            .await
            .unwrap();

        let mut ended = false;

        for op in input.ops.into_iter().take(64) {
            match op {
                MeteringOp::Record {
                    bytes_in,
                    bytes_out,
                } => {
                    let result = service.record_usage(&session_id, bytes_in, bytes_out).await;
                    match result {
                        Ok(()) => {
                            assert!(!ended);
                            let snapshot = service.get_usage(&session_id).await.unwrap();
                            assert_snapshot(&snapshot);
                        }
                        Err(MeteringError::SessionNotFound(_)) => assert!(ended),
                        Err(MeteringError::BandwidthExceeded {
                            limit,
                            current,
                            requested,
                        }) => {
                            assert!(!ended);
                            assert_eq!(Some(limit), config.bandwidth_limit);
                            assert!(
                                current.saturating_add(requested) > limit,
                                "bandwidth errors must exceed the configured limit"
                            );
                        }
                        Err(MeteringError::CounterOverflow) => {}
                        Err(MeteringError::SessionInactive | MeteringError::RateLimitExceeded) => {
                            panic!("unexpected metering error")
                        }
                    }
                }
                MeteringOp::GetUsage => match service.get_usage(&session_id).await {
                    Some(snapshot) => {
                        assert!(!ended);
                        assert_snapshot(&snapshot);
                    }
                    None => assert!(ended),
                },
                MeteringOp::ActiveSessions => {
                    let sessions = service.active_sessions().await;
                    assert_eq!(sessions.iter().any(|s| s.session_id == session_id), !ended);
                    for snapshot in sessions {
                        assert!(snapshot.active);
                        assert_snapshot(&snapshot);
                    }
                }
                MeteringOp::ConsumerSessions => {
                    let sessions = service.consumer_sessions(&config.consumer_did).await;
                    assert_eq!(sessions.iter().any(|s| s.session_id == session_id), !ended);
                    for snapshot in sessions {
                        assert_eq!(snapshot.consumer_did, config.consumer_did);
                        assert_snapshot(&snapshot);
                    }
                }
                MeteringOp::ProviderSessions => {
                    let sessions = service.provider_sessions(&config.provider_did).await;
                    assert_eq!(sessions.iter().any(|s| s.session_id == session_id), !ended);
                    for snapshot in sessions {
                        assert_eq!(snapshot.provider_did, config.provider_did);
                        assert_snapshot(&snapshot);
                    }
                }
                MeteringOp::ProviderTotal => {
                    let sessions = service.provider_sessions(&config.provider_did).await;
                    let expected = sessions
                        .iter()
                        .fold(0_u64, |total, s| total.saturating_add(s.total_bytes()));
                    assert_eq!(
                        service.provider_total_bytes(&config.provider_did).await,
                        expected
                    );
                }
                MeteringOp::End => {
                    let result = service.end_session(&session_id).await;
                    if ended {
                        assert!(matches!(result, Err(MeteringError::SessionNotFound(_))));
                    } else {
                        let snapshot = result.unwrap();
                        assert!(!snapshot.active);
                        assert_snapshot(&snapshot);
                        assert!(service.get_usage(&session_id).await.is_none());
                        ended = true;
                    }
                }
            }
        }
    });
});

fn assert_snapshot(snapshot: &MeteringSnapshot) {
    let total = snapshot.total_bytes();
    assert!(snapshot.total_kb() >= total / 1024);

    if let Some(limit) = snapshot.bandwidth_limit {
        assert!(total <= limit);
        assert_eq!(snapshot.remaining, Some(limit - total));
    } else {
        assert_eq!(snapshot.remaining, None);
    }
}
