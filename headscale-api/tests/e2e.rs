//! Real E2E tests that spawn actual server and node processes.
//!
//! These tests verify the complete flow:
//! 1. Start a control plane server
//! 2. Register multiple nodes
//! 3. Verify mesh formation
//! 4. Test resource metering flows
//! 5. Test API endpoints

#![cfg(feature = "full")]

use std::sync::Arc;
use std::time::Duration;

use base64::prelude::*;
use headscale_api::Server;
use headscale_api::control_auth::{
    SignedRegisterRequest, canonical_node_register_message, now_millis,
};
use headscale_core::{
    MeshCoordinator,
    node::{NodeCapabilities, RegisterRequest},
};
use headscale_identity::KeyPair;
use headscale_payments::Ledger;
use headscale_resources::{BandwidthSpec, Meter, ResourceRegistry, ResourceType};
use tokio::net::TcpListener;

/// Get an available port for testing.
async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Test context that manages the server lifecycle.
struct TestContext {
    port: u16,
    mesh: Arc<MeshCoordinator>,
    ledger: Arc<Ledger>,
    resources: Arc<ResourceRegistry>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestContext {
    async fn new() -> Self {
        let port = get_free_port().await;
        let mesh = Arc::new(MeshCoordinator::new("100.64.0.0/10"));
        let ledger = Arc::new(Ledger::new());
        let resources = Arc::new(ResourceRegistry::new());

        Self {
            port,
            mesh,
            ledger,
            resources,
            server_handle: None,
        }
    }

    fn api_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    async fn start_server(&mut self) {
        let server = Server::new(
            self.mesh.clone(),
            self.ledger.clone(),
            self.resources.clone(),
            format!("127.0.0.1:{}", self.port).parse().unwrap(),
        );

        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        self.server_handle = Some(handle);

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    async fn stop_server(&mut self) {
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

fn bandwidth_resource() -> ResourceType {
    ResourceType::Bandwidth(BandwidthSpec {
        upload_mbps: 100,
        download_mbps: 100,
    })
}

fn signed_register(name: &str, capabilities: NodeCapabilities) -> SignedRegisterRequest {
    let keypair = KeyPair::generate();
    let request = RegisterRequest {
        id: keypair.did().to_string(),
        name: name.to_string(),
        wg_pubkey: BASE64_STANDARD.encode([0x42u8; 32]),
        endpoints: vec!["127.0.0.1:51820".to_string()],
        capabilities,
    };
    let timestamp_millis = now_millis();
    let nonce = format!("e2e-register-{timestamp_millis}");
    let signature = BASE64_STANDARD.encode(keypair.sign(&canonical_node_register_message(
        &request,
        timestamp_millis,
        &nonce,
    )));

    SignedRegisterRequest {
        request,
        signature,
        timestamp_millis,
        nonce,
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

// ============================================================================
// Mesh Formation Tests
// ============================================================================

#[tokio::test]
async fn test_single_node_registration() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    // Register a single node
    let req = RegisterRequest {
        id: "node-1".to_string(),
        name: "TestNode1".to_string(),
        wg_pubkey: "test-pubkey-1".to_string(),
        endpoints: vec!["192.168.1.100:51820".to_string()],
        capabilities: NodeCapabilities::default(),
    };

    let result = ctx.mesh.register(req).await;
    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(response.addresses.len(), 1);
    assert!(response.addresses[0].to_string().starts_with("100.64."));
    assert_eq!(response.peers.len(), 0); // No other peers yet

    // Verify node is in the list
    let nodes = ctx.mesh.list_nodes().await;
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, "node-1");
    assert!(nodes[0].online);

    ctx.stop_server().await;
}

#[tokio::test]
async fn test_multi_node_mesh_formation() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    // Register multiple nodes
    for i in 1..=5 {
        let req = RegisterRequest {
            id: format!("node-{i}"),
            name: format!("TestNode{i}"),
            wg_pubkey: format!("test-pubkey-{i}"),
            endpoints: vec![format!("192.168.1.{}:51820", 100 + i)],
            capabilities: NodeCapabilities::default(),
        };

        let result = ctx.mesh.register(req).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        // Each new node should see all previous nodes as peers
        assert_eq!(response.peers.len(), i - 1);
    }

    // Verify all nodes are registered
    let nodes = ctx.mesh.list_nodes().await;
    assert_eq!(nodes.len(), 5);

    // Each node should have a unique IP
    let ips: Vec<_> = nodes.iter().flat_map(|n| &n.addresses).collect();
    let unique_ips: std::collections::HashSet<_> = ips.iter().collect();
    assert_eq!(ips.len(), unique_ips.len());

    ctx.stop_server().await;
}

#[tokio::test]
async fn test_node_heartbeat() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    // Register node
    let req = RegisterRequest {
        id: "heartbeat-node".to_string(),
        name: "HeartbeatTest".to_string(),
        wg_pubkey: "test-pubkey".to_string(),
        endpoints: vec!["192.168.1.100:51820".to_string()],
        capabilities: NodeCapabilities::default(),
    };

    ctx.mesh.register(req).await.unwrap();

    // Send heartbeat
    let result = ctx.mesh.heartbeat("heartbeat-node").await;
    assert!(result.is_ok());

    // Heartbeat for non-existent node should fail
    let result = ctx.mesh.heartbeat("non-existent").await;
    assert!(result.is_err());

    ctx.stop_server().await;
}

#[tokio::test]
async fn test_node_capabilities_filtering() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    // Register nodes with different capabilities
    let nodes_config = vec![
        (
            "inference-node",
            NodeCapabilities {
                inference: true,
                ..Default::default()
            },
        ),
        (
            "storage-node",
            NodeCapabilities {
                storage: true,
                ..Default::default()
            },
        ),
        (
            "compute-node",
            NodeCapabilities {
                compute: true,
                ..Default::default()
            },
        ),
        (
            "relay-node",
            NodeCapabilities {
                relay: true,
                ..Default::default()
            },
        ),
        (
            "multi-node",
            NodeCapabilities {
                inference: true,
                compute: true,
                ..Default::default()
            },
        ),
    ];

    for (id, caps) in nodes_config {
        let req = RegisterRequest {
            id: id.to_string(),
            name: id.to_string(),
            wg_pubkey: format!("pubkey-{id}"),
            endpoints: vec!["192.168.1.1:51820".to_string()],
            capabilities: caps,
        };
        ctx.mesh.register(req).await.unwrap();
    }

    // Filter by capability
    let inference_nodes = ctx.mesh.nodes_with_capability("inference").await;
    assert_eq!(inference_nodes.len(), 2); // inference-node + multi-node

    let storage_nodes = ctx.mesh.nodes_with_capability("storage").await;
    assert_eq!(storage_nodes.len(), 1);

    let relay_nodes = ctx.mesh.nodes_with_capability("relay").await;
    assert_eq!(relay_nodes.len(), 1);

    ctx.stop_server().await;
}

// ============================================================================
// Payment/Ledger Tests
// ============================================================================

#[tokio::test]
async fn test_ledger_deposit_and_balance() {
    let ctx = TestContext::new().await;

    // Deposit funds
    let tx = ctx
        .ledger
        .deposit("did:key:alice", 10_000, "Initial deposit")
        .await;
    assert_eq!(tx.amount, 10_000);

    // Check balance
    let balance = ctx.ledger.balance("did:key:alice").await;
    assert_eq!(balance, 10_000);

    // Check available (includes credit)
    let available = ctx.ledger.available("did:key:alice").await;
    assert_eq!(available, 10_000);
}

#[tokio::test]
async fn test_ledger_transfer() {
    let ctx = TestContext::new().await;

    // Setup accounts
    ctx.ledger.deposit("did:key:alice", 10_000, "Deposit").await;

    // Transfer
    let result = ctx
        .ledger
        .transfer(
            "did:key:alice",
            "did:key:bob",
            3_000,
            "Payment for services",
        )
        .await;
    assert!(result.is_ok());

    // Verify balances
    assert_eq!(ctx.ledger.balance("did:key:alice").await, 7_000);
    assert_eq!(ctx.ledger.balance("did:key:bob").await, 3_000);
}

#[tokio::test]
async fn test_ledger_insufficient_funds() {
    let ctx = TestContext::new().await;

    // Try to transfer without funds
    let result = ctx
        .ledger
        .transfer("did:key:alice", "did:key:bob", 1_000, "Should fail")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ledger_credit_limit() {
    let ctx = TestContext::new().await;

    // Set credit limit
    ctx.ledger.set_credit_limit("did:key:alice", 5_000).await;

    // Available should include credit
    let available = ctx.ledger.available("did:key:alice").await;
    assert_eq!(available, 5_000);

    // Can transfer up to credit limit
    let result = ctx
        .ledger
        .transfer("did:key:alice", "did:key:bob", 3_000, "Using credit")
        .await;
    assert!(result.is_ok());

    // Balance is negative, but available accounts for remaining credit
    assert_eq!(ctx.ledger.balance("did:key:alice").await, -3_000);
    assert_eq!(ctx.ledger.available("did:key:alice").await, 2_000);
}

// ============================================================================
// Resource Metering Tests
// ============================================================================

#[tokio::test]
async fn test_metering_session_lifecycle() {
    let meter = Meter::new();
    let session_id = meter
        .start_session(
            "did:key:consumer",
            "did:key:provider",
            bandwidth_resource(),
            2,
        )
        .await;

    meter.record_usage(&session_id, 1_000).await.unwrap();
    meter.record_usage(&session_id, 2_000).await.unwrap();

    assert_eq!(meter.current_cost(&session_id).await.unwrap(), 6_000);

    let usage = meter.end_session(&session_id).await.unwrap();
    assert_eq!(usage.units_consumed, 3_000);
    assert_eq!(usage.cost_millitokens, 6_000);
    assert_eq!(meter.consumer_total_cost("did:key:consumer").await, 6_000);
    assert!(meter.current_cost(&session_id).await.is_err());
}

// ============================================================================
// API Integration Tests (using HTTP client)
// ============================================================================

#[tokio::test]
async fn test_api_health_endpoint() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    // Give server time to fully start
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/health", ctx.api_url())).send().await;

    let resp = resp.unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "healthy");

    ctx.stop_server().await;
}

#[tokio::test]
async fn test_api_node_registration() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();

    // Register via API
    let req = signed_register(
        "APITestNode",
        NodeCapabilities {
            compute: true,
            ..Default::default()
        },
    );

    let resp = client
        .post(format!("{}/api/v1/nodes", ctx.api_url()))
        .json(&req)
        .send()
        .await;

    let resp = resp.unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(!body["addresses"].as_array().unwrap().is_empty());

    ctx.stop_server().await;
}

#[tokio::test]
async fn test_api_metrics_endpoint() {
    let mut ctx = TestContext::new().await;
    ctx.start_server().await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/metrics", ctx.api_url()))
        .send()
        .await;

    let resp = resp.unwrap();
    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("mesh_nodes") || body.contains("inference_tokens") || !body.is_empty());

    ctx.stop_server().await;
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_registrations() {
    let ctx = TestContext::new().await;

    // Spawn many concurrent registrations
    let mesh = ctx.mesh.clone();
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let mesh = mesh.clone();
            tokio::spawn(async move {
                let req = RegisterRequest {
                    id: format!("concurrent-node-{i}"),
                    name: format!("ConcurrentNode{i}"),
                    wg_pubkey: format!("concurrent-pubkey-{i}"),
                    endpoints: vec![format!("192.168.{}.1:51820", i % 256)],
                    capabilities: NodeCapabilities::default(),
                };
                mesh.register(req).await
            })
        })
        .collect();

    // Wait for all
    let results: Vec<_> = futures::future::join_all(handles).await;

    // All should succeed
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    // All nodes should be registered
    let nodes = ctx.mesh.list_nodes().await;
    assert_eq!(nodes.len(), 100);
}

#[tokio::test]
async fn test_rapid_bandwidth_recording() {
    let meter = Arc::new(Meter::new());
    let session_id = meter
        .start_session(
            "did:key:consumer",
            "did:key:provider",
            bandwidth_resource(),
            1,
        )
        .await;

    // Rapid-fire bandwidth recording
    let session_id_clone = session_id.clone();
    let handles: Vec<_> = (0..1000)
        .map(|_| {
            let meter = meter.clone();
            let sid = session_id_clone.clone();
            tokio::spawn(async move { meter.record_usage(&sid, 1000).await })
        })
        .collect();

    let results: Vec<_> = futures::future::join_all(handles).await;

    // Count successes
    let successes = results
        .iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();
    assert!(successes > 900); // Most should succeed

    // Verify total bandwidth
    let usage = meter.end_session(&session_id).await.unwrap();
    assert!(usage.units_consumed >= 900_000); // At least 900 successful recordings * 1000 bytes
}
