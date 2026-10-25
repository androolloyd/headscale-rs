use super::*;
use crate::policy::{PolicyStore, parse_hujson_policy, persistence::PolicyPersistence};
use axum::{body::Body, http::Request};
use tower::ServiceExt;

const DENY: &str = "// retain comments across a restart\n{\"acls\":[],}";

fn put(raw: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri("/api/v1/policy")
        .header("authorization", "Bearer test-token")
        .body(Body::from(raw.to_owned()))
        .unwrap()
}

fn state(pool: sqlx::SqlitePool, policy: PolicyStore) -> AdminState {
    AdminState::builder()
        .bearer_token("test-token")
        .policy(policy)
        .policy_persistence(Arc::new(pool))
        .build()
}

async fn database() -> (tempfile::TempDir, headscale_db::Database) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("mesh.db").display());
    let db = headscale_db::Database::new(&url).await.unwrap();
    db.migrate().await.unwrap();
    (dir, db)
}

#[tokio::test]
async fn http_policy_survives_database_reopen_without_allow_all() {
    let (dir, db) = database().await;
    let initial = state(db.pool().clone(), PolicyStore::new());
    assert!(!initial.load_policy_from_persistence().await.unwrap());
    let app = router(initial.clone());
    assert_eq!(
        app.clone().oneshot(put(DENY)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        initial.policy.filter_rules(),
        [] as [crate::tailscale_wire::wire::FilterRule; 0]
    );
    assert!(initial.policy.is_loaded());
    assert_eq!(
        app.oneshot(put("invalid")).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let timestamp = initial.policy.updated_at();
    drop(initial);
    db.pool().close().await;
    let url = format!("sqlite://{}", dir.path().join("mesh.db").display());
    let db = headscale_db::Database::new(&url).await.unwrap();
    let restored = state(db.pool().clone(), PolicyStore::new());
    assert!(restored.load_policy_from_persistence().await.unwrap());
    assert_eq!(restored.policy.raw().as_deref(), Some(DENY));
    assert_eq!(restored.policy.updated_at(), timestamp);
    assert!(restored.policy.is_loaded());
    assert_eq!(
        restored.policy.filter_rules(),
        [] as [crate::tailscale_wire::wire::FilterRule; 0]
    );
}

#[tokio::test]
async fn failed_write_does_not_publish_or_notify_and_bad_storage_prevents_load() {
    let (_dir, db) = database().await;
    let live = PolicyStore::new();
    live.set(parse_hujson_policy(DENY).unwrap(), DENY.into());
    let initial = state(db.pool().clone(), live.clone());
    let changed = live.wait_for_change();
    tokio::pin!(changed);
    assert!(futures::poll!(changed.as_mut()).is_pending());
    sqlx::query("DROP TABLE policies")
        .execute(db.pool())
        .await
        .unwrap();
    let response = router(initial.clone())
        .oneshot(put(
            r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(live.raw().as_deref(), Some(DENY));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), changed)
            .await
            .is_err()
    );
    assert!(initial.load_policy_from_persistence().await.is_err());
}

#[tokio::test]
async fn corrupted_policy_is_not_replaced_with_empty_defaults() {
    let (_dir, db) = database().await;
    PolicyPersistence::set_policy(db.pool(), "corrupt")
        .await
        .unwrap();
    let live = PolicyStore::new();
    live.set(parse_hujson_policy(DENY).unwrap(), DENY.into());
    assert!(
        state(db.pool().clone(), live.clone())
            .load_policy_from_persistence()
            .await
            .is_err()
    );
    assert_eq!(live.raw().as_deref(), Some(DENY));
}

#[tokio::test]
async fn concurrent_http_writers_leave_the_cache_at_the_latest_commit() {
    let (_dir, db) = database().await;
    let initial = state(db.pool().clone(), PolicyStore::new());
    let app = router(initial.clone());
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..12 {
        let app = app.clone();
        tasks.spawn(async move {
            app.oneshot(put(&format!("// writer {index}\n{{\"acls\":[]}}")))
                .await
                .unwrap()
                .status()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::OK);
    }
    let saved = PolicyPersistence::get_latest_policy(db.pool())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(initial.policy.raw().as_deref(), Some(saved.policy.as_str()));
    assert_eq!(initial.policy.updated_at(), Some(saved.updated_at));
}

#[tokio::test]
async fn externally_managed_policy_rejects_admin_replacement() {
    let (_dir, db) = database().await;
    let initial = AdminState::builder()
        .bearer_token("test-token")
        .policy_persistence(Arc::new(db.pool().clone()))
        .policy_read_only(true)
        .build();
    assert_eq!(
        router(initial.clone())
            .oneshot(put(DENY))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!initial.policy.is_loaded());
    assert!(
        PolicyPersistence::get_latest_policy(db.pool())
            .await
            .unwrap()
            .is_none()
    );
}
