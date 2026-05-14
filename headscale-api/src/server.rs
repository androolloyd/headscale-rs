//! API server combining HTTP and gRPC.

use std::net::SocketAddr;
use std::sync::Arc;

use headscale_core::MeshCoordinator;
use headscale_payments::Ledger;
use headscale_resources::ResourceRegistry;

/// Combined API server.
pub struct Server {
    mesh: Arc<MeshCoordinator>,
    ledger: Arc<Ledger>,
    resources: Arc<ResourceRegistry>,
    listen_addr: SocketAddr,
}

impl Server {
    pub fn new(
        mesh: Arc<MeshCoordinator>,
        ledger: Arc<Ledger>,
        resources: Arc<ResourceRegistry>,
        listen_addr: SocketAddr,
    ) -> Self {
        Self {
            mesh,
            ledger,
            resources,
            listen_addr,
        }
    }

    /// Run the server.
    pub async fn run(self) -> Result<(), ServerError> {
        tracing::info!("Starting API server on {}", self.listen_addr);

        // Build HTTP router
        let app = crate::http::build_router(
            self.mesh.clone(),
            self.ledger.clone(),
            self.resources.clone(),
        );

        // Run axum server
        let listener = tokio::net::TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        axum::serve(listener, app)
            .await
            .map_err(|e| ServerError::Serve(e.to_string()))?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Failed to bind: {0}")]
    Bind(String),
    #[error("Server error: {0}")]
    Serve(String),
}
