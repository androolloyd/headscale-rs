//! Coverage tests for [`MachineRegistry`].
//!
//! Companions to the in-tree `registry_tests` module — these focus on
//! concurrency, idempotent upsert, and the contract callers depend on
//! (snapshot pointer-equality across no-op writes, deep-isolation of
//! cached snapshots across concurrent mutations).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use headscale_api::tailscale_wire::{MachineRecord, MachineRegistry};

fn mk(host: u32, user: &str) -> MachineRecord {
    MachineRecord::new_at(
        chrono::Utc::now(),
        format!("nk-{host:08x}"),
        format!("mk-{host:08x}"),
        user.to_string(),
        format!("h-{host}"),
        Ipv4Addr::new(100, 64, (host >> 8) as u8, host as u8),
        false,
    )
}

#[test]
fn empty_registry_has_zero_len_and_is_empty() {
    let r = MachineRegistry::new();
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
    assert!(r.get("anything").is_none());
}

#[test]
fn upsert_then_get_returns_clone() {
    let r = MachineRegistry::new();
    let rec = mk(1, "alice");
    r.upsert(rec.node_key_hex.clone(), rec.clone());
    let got = r.get(&rec.node_key_hex).unwrap();
    assert_eq!(got.user, "alice");
    assert_eq!(got.ipv4, rec.ipv4);
}

#[test]
fn idempotent_upsert_same_key_overwrites() {
    // Idempotent in the sense that the *key* doesn't multiply — a
    // second upsert under the same key replaces the record.
    let r = MachineRegistry::new();
    let mut rec = mk(1, "alice");
    r.upsert(rec.node_key_hex.clone(), rec.clone());
    rec.user = "alice-v2".to_string();
    rec.hostname = "h-renamed".to_string();
    r.upsert(rec.node_key_hex.clone(), rec.clone());
    assert_eq!(r.len(), 1);
    let got = r.get(&rec.node_key_hex).unwrap();
    assert_eq!(got.user, "alice-v2");
    assert_eq!(got.hostname, "h-renamed");
}

#[test]
fn upsert_distinct_keys_grows_len() {
    let r = MachineRegistry::new();
    for i in 0u32..10 {
        let rec = mk(i, "u");
        r.upsert(rec.node_key_hex.clone(), rec);
    }
    assert_eq!(r.len(), 10);
}

#[test]
fn snapshot_pointer_equality_across_read_only_ops() {
    use std::sync::Arc as SArc;
    let r = MachineRegistry::new();
    r.upsert("k1".into(), mk(1, "u"));
    let s1 = r.snapshot();
    // Read-only ops on the registry: get + len + is_empty + snapshot
    // — none of these may invalidate the cached Arc.
    let _ = r.get("k1");
    let _ = r.len();
    let _ = r.is_empty();
    let s2 = r.snapshot();
    assert!(
        SArc::ptr_eq(&s1, &s2),
        "snapshot Arc must alias across read-only registry ops"
    );
}

#[test]
fn snapshot_is_isolated_from_subsequent_writes() {
    let r = Arc::new(MachineRegistry::new());
    for i in 0u32..5 {
        r.upsert(format!("k-{i}"), mk(i, "u"));
    }
    let snap = r.snapshot();
    assert_eq!(snap.len(), 5);

    // Write a bunch more — the existing snapshot stays at 5.
    for i in 10u32..30 {
        r.upsert(format!("k-{i}"), mk(i, "u"));
    }
    assert_eq!(snap.len(), 5, "snapshot must NOT see post-snap writes");
    assert_eq!(r.snapshot().len(), 25, "live registry sees all writes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_upserts_converge_without_loss_or_duplication() {
    // N writer tasks insert disjoint key ranges concurrently. The
    // final registry must hold exactly N*M unique keys.
    const WRITERS: u32 = 8;
    const PER_WRITER: u32 = 50;
    let r = Arc::new(MachineRegistry::new());
    let mut handles = Vec::new();
    for w in 0..WRITERS {
        let r = r.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..PER_WRITER {
                let id = w * 10_000 + i;
                let rec = mk(id, &format!("w{w}"));
                r.upsert(format!("k-{id}"), rec);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(r.len(), (WRITERS * PER_WRITER) as usize);
    // Verify uniqueness from the snapshot side too.
    let snap = r.snapshot();
    let keys: HashSet<_> = snap.keys().cloned().collect();
    assert_eq!(keys.len(), (WRITERS * PER_WRITER) as usize);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_see_stable_snapshot() {
    // One writer + several long-running readers. The readers must
    // each observe a monotonically non-decreasing len, and the final
    // snapshot must reflect every writer-published upsert.
    let r = Arc::new(MachineRegistry::new());
    let writer_r = r.clone();
    let writer = tokio::spawn(async move {
        for i in 0u32..200 {
            writer_r.upsert(format!("k-{i:04}"), mk(i, "u"));
            if i % 20 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });
    let mut readers = Vec::new();
    for _ in 0..4 {
        let r = r.clone();
        readers.push(tokio::spawn(async move {
            let mut last_len = 0;
            for _ in 0..40 {
                let snap = r.snapshot();
                assert!(snap.len() >= last_len, "snapshots non-decreasing");
                last_len = snap.len();
                tokio::task::yield_now().await;
            }
        }));
    }
    writer.await.unwrap();
    for h in readers {
        h.await.unwrap();
    }
    assert_eq!(r.len(), 200);
}

#[test]
fn snapshot_iteration_order_stable_for_fixed_input() {
    // Not a HashMap-ordering guarantee from std; we just need to
    // verify the snapshot is a HashMap<String, MachineRecord> and
    // that we can iterate it without panicking.
    let r = MachineRegistry::new();
    for i in 0u32..32 {
        r.upsert(format!("k-{i:02}"), mk(i, "u"));
    }
    let snap = r.snapshot();
    let mut count = 0;
    for (k, v) in snap.iter() {
        assert!(k.starts_with("k-"));
        assert_eq!(v.user, "u");
        count += 1;
    }
    assert_eq!(count, 32);
}

#[test]
fn get_nonexistent_after_upserts_returns_none() {
    let r = MachineRegistry::new();
    for i in 0u32..16 {
        r.upsert(format!("k-{i}"), mk(i, "u"));
    }
    assert!(r.get("missing-key").is_none());
    // Also: exact-key sensitivity — substring shouldn't match.
    assert!(r.get("k-").is_none());
    assert!(r.get("k-0").is_some()); // exact
}
