//! Server mode - runs the control plane.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use headscale_api::Server;
use headscale_core::MeshCoordinator;
use headscale_payments::Ledger;
use headscale_resources::ResourceRegistry;

/// Run the control plane server.
pub(crate) async fn run_server(listen: &str, db_path: &Path, mesh_cidr: &str) -> Result<()> {
    tracing::info!("Starting headscale control plane");
    tracing::info!("  Listen: {}", listen);
    tracing::info!("  Database: {}", db_path.display());
    tracing::info!("  Mesh CIDR: {}", mesh_cidr);

    // Ensure database directory exists
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory: {}", parent.display()))?;
        }
    }

    // Create core components
    let mesh = Arc::new(MeshCoordinator::new(mesh_cidr));
    let ledger = Arc::new(Ledger::new());
    let resources = Arc::new(ResourceRegistry::new());

    // Parse listen address
    let listen_addr = listen
        .parse()
        .with_context(|| format!("Invalid listen address: {}", listen))?;

    // Create and run server
    let server = Server::new(mesh, ledger, resources, listen_addr);

    tracing::info!("Control plane ready");
    server.run().await.context("Server error")?;

    Ok(())
}
