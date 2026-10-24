//! Keep bcrypt off the async executor and bound submitted blocking work.

use std::sync::{Arc, LazyLock};
use tokio::sync::Semaphore;

// API and preauth keys share the budget. Acquire before submitting a job so
// Tokio's blocking queue cannot accumulate an unbounded number of hashes.
static BCRYPT_WORKERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, 8);
    Arc::new(Semaphore::new(workers))
});

async fn run<T, F>(work: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let permit = BCRYPT_WORKERS
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| format!("credential worker unavailable: {error}"))?;
    tokio::task::spawn_blocking(move || {
        // Keep the permit in the worker: cancelling the requesting future
        // cannot free a slot while its non-cancellable bcrypt work is running.
        let _permit = permit;
        work()
    })
    .await
    .map_err(|error| format!("credential worker failed: {error}"))?
}

pub(crate) async fn hash(secret: String, cost: u32) -> Result<String, String> {
    run(move || crate::go_bcrypt::hash(secret.as_bytes(), cost)).await
}

pub(crate) async fn verify_bytes(secret: &str, encoded: &[u8]) -> Result<bool, String> {
    let secret = secret.to_owned();
    let encoded = encoded.to_owned();
    run(move || crate::go_bcrypt::verify(secret.as_bytes(), &encoded)).await
}
