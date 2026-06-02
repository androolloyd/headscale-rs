use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

async fn retry_docker_op_for_parity<F>(deadline: Instant, mut op: F) -> Result<(), &'static str>
where
    F: FnMut() -> Result<(), &'static str>,
{
    loop {
        match op() {
            Ok(()) => return Ok(()),
            Err(err) if Instant::now() >= deadline => return Err(err),
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}

#[tokio::test]
async fn retry_docker_op_recovers_from_transient() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = attempts.clone();

    retry_docker_op_for_parity(Instant::now() + Duration::from_secs(1), move || {
        if seen.fetch_add(1, Ordering::SeqCst) < 2 {
            Err("endpoint with name foo already exists in network bar")
        } else {
            Ok(())
        }
    })
    .await
    .expect("retryDockerOp should recover from transient endpoint collisions");

    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_docker_op_respects_context_cancellation() {
    let start = Instant::now();
    let err = retry_docker_op_for_parity(start + Duration::from_millis(200), || {
        Err("permanent error")
    })
    .await
    .expect_err("retryDockerOp should fail when op always errors");

    assert_eq!(err, "permanent error");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "retryDockerOp should honor the caller deadline"
    );
}
